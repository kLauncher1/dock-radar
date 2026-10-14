package alert

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Alert severity levels.
const (
	LevelInfo     = "info"
	LevelWarning  = "warning"
	LevelCritical = "critical"
)

// Event encapsulates a discrete alert occurrence.
type Event struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	Level     string         `json:"level"`
	Source    string         `json:"source"`
	EventType string         `json:"event_type"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
}

// Dispatcher broadcasts alert events to configured webhook channels with rate control.
type Dispatcher struct {
	httpClient  *http.Client
	configStore *ConfigStore
	bufferMu    sync.RWMutex
	events      []Event
	maxBuffer   int
	cooldownMap sync.Map
}

// NewDispatcher creates an alert dispatcher with a 10-second timeout HTTP client.
func NewDispatcher(cfgStore *ConfigStore) *Dispatcher {
	return NewDispatcherWithClient(cfgStore, &http.Client{
		Timeout: 10 * time.Second,
	})
}

// NewDispatcherWithClient initializes a dispatcher using a custom HTTP transport (e.g. for testing).
func NewDispatcherWithClient(cfgStore *ConfigStore, client *http.Client) *Dispatcher {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Dispatcher{
		httpClient:  client,
		configStore: cfgStore,
		events:      make([]Event, 0, 100),
		maxBuffer:   100,
	}
}

// RecordEvent appends an event to the recent in-memory circular buffer (capped at maxBuffer).
func (d *Dispatcher) RecordEvent(event Event) {
	d.bufferMu.Lock()
	defer d.bufferMu.Unlock()

	if len(d.events) >= d.maxBuffer {
		// Evict oldest element
		d.events = d.events[1:]
	}
	d.events = append(d.events, event)
}

// RecentEvents returns the most recent buffered events (newest first).
func (d *Dispatcher) RecentEvents(limit int) []Event {
	d.bufferMu.RLock()
	defer d.bufferMu.RUnlock()

	total := len(d.events)
	if limit <= 0 || limit > total {
		limit = total
	}

	result := make([]Event, limit)
	for i := 0; i < limit; i++ {
		result[i] = d.events[total-1-i]
	}
	return result
}

// Dispatch evaluates cooldown, logs the event, and delivers webhooks to Discord and Slack.
func (d *Dispatcher) Dispatch(ctx context.Context, event Event) error {
	if event.ID == "" {
		event.ID = generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	d.RecordEvent(event)

	cfg := d.configStore.Get()
	if !cfg.Enabled {
		return nil
	}

	// Cooldown enforcement for non-test events
	if event.EventType != "test" {
		cooldownKey := fmt.Sprintf("%s:%s", event.Source, event.EventType)
		if lastVal, ok := d.cooldownMap.Load(cooldownKey); ok {
			if lastTime, ok := lastVal.(time.Time); ok {
				cooldownDuration := time.Duration(cfg.CooldownSeconds) * time.Second
				if time.Since(lastTime) < cooldownDuration {
					// Cooldown active; event is buffered but webhook broadcast is skipped
					return nil
				}
			}
		}
	}

	var dispatchErrors []string

	// 1. Discord Webhook
	if cfg.DiscordWebhookURL != "" {
		if err := d.sendDiscord(ctx, cfg.DiscordWebhookURL, event); err != nil {
			dispatchErrors = append(dispatchErrors, fmt.Sprintf("discord: %v", err))
		}
	}

	// 2. Slack Webhook
	if cfg.SlackWebhookURL != "" {
		if err := d.sendSlack(ctx, cfg.SlackWebhookURL, event); err != nil {
			dispatchErrors = append(dispatchErrors, fmt.Sprintf("slack: %v", err))
		}
	}

	// Update cooldown timestamp if successfully evaluated
	if event.EventType != "test" {
		cooldownKey := fmt.Sprintf("%s:%s", event.Source, event.EventType)
		d.cooldownMap.Store(cooldownKey, time.Now())
	}

	if len(dispatchErrors) > 0 {
		return fmt.Errorf("alert dispatch errors: %s", strings.Join(dispatchErrors, "; "))
	}
	return nil
}

// SendTestNotification bypasses standard monitoring loops to verify webhook endpoint reachability.
func (d *Dispatcher) SendTestNotification(ctx context.Context, channel string) error {
	cfg := d.configStore.Get()
	targetChannel := strings.ToLower(strings.TrimSpace(channel))
	if targetChannel == "" {
		targetChannel = "all"
	}

	testEvent := Event{
		ID:        generateEventID(),
		Timestamp: time.Now().UTC(),
		Level:     LevelInfo,
		Source:    "system:test",
		EventType: "test",
		Message:   "Dock-Radar alert channel verification notification",
		Details: map[string]any{
			"channel": targetChannel,
			"status":  "verified",
		},
	}
	d.RecordEvent(testEvent)

	var errs []string
	sentAny := false

	if targetChannel == "discord" || targetChannel == "all" {
		if cfg.DiscordWebhookURL == "" {
			if targetChannel == "discord" {
				return fmt.Errorf("discord webhook URL is not configured")
			}
		} else {
			if err := d.sendDiscord(ctx, cfg.DiscordWebhookURL, testEvent); err != nil {
				errs = append(errs, fmt.Sprintf("discord: %v", err))
			} else {
				sentAny = true
			}
		}
	}

	if targetChannel == "slack" || targetChannel == "all" {
		if cfg.SlackWebhookURL == "" {
			if targetChannel == "slack" {
				return fmt.Errorf("slack webhook URL is not configured")
			}
		} else {
			if err := d.sendSlack(ctx, cfg.SlackWebhookURL, testEvent); err != nil {
				errs = append(errs, fmt.Sprintf("slack: %v", err))
			} else {
				sentAny = true
			}
		}
	}

	if targetChannel == "all" && !sentAny && len(errs) == 0 {
		return fmt.Errorf("no webhook URLs configured for test notification")
	}

	if len(errs) > 0 {
		return fmt.Errorf("test notification delivery failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

// BuildDiscordPayload generates a Discord embed JSON representation.
func BuildDiscordPayload(event Event) ([]byte, error) {
	// Color code: Red = 15158332, Orange = 15105570, Green = 3066993
	color := 3066993
	switch strings.ToLower(event.Level) {
	case LevelCritical:
		color = 15158332
	case LevelWarning:
		color = 15105570
	}

	fields := []map[string]any{
		{"name": "Level", "value": strings.ToUpper(event.Level), "inline": true},
		{"name": "Source", "value": event.Source, "inline": true},
		{"name": "Event Type", "value": event.EventType, "inline": true},
	}

	for k, v := range event.Details {
		fields = append(fields, map[string]any{
			"name":   k,
			"value":  fmt.Sprintf("%v", v),
			"inline": true,
		})
	}

	payload := map[string]any{
		"embeds": []map[string]any{
			{
				"title":       fmt.Sprintf("Dock-Radar Alert: %s", event.EventType),
				"description": event.Message,
				"color":       color,
				"fields":      fields,
				"timestamp":   event.Timestamp.Format(time.RFC3339),
				"footer": map[string]string{
					"text": "Dock-Radar Engine",
				},
			},
		},
	}
	return json.Marshal(payload)
}

// BuildSlackPayload generates a Slack webhook JSON attachment representation.
func BuildSlackPayload(event Event) ([]byte, error) {
	colorHex := "#2ecc71"
	switch strings.ToLower(event.Level) {
	case LevelCritical:
		colorHex = "#e74c3c"
	case LevelWarning:
		colorHex = "#e67e22"
	}

	fields := []map[string]any{
		{"title": "Level", "value": strings.ToUpper(event.Level), "short": true},
		{"title": "Source", "value": event.Source, "short": true},
		{"title": "Event Type", "value": event.EventType, "short": true},
	}

	for k, v := range event.Details {
		fields = append(fields, map[string]any{
			"title": k,
			"value": fmt.Sprintf("%v", v),
			"short": true,
		})
	}

	payload := map[string]any{
		"text": fmt.Sprintf("*[Dock-Radar %s]* %s", strings.ToUpper(event.Level), event.Message),
		"attachments": []map[string]any{
			{
				"color":  colorHex,
				"title":  event.EventType,
				"text":   event.Message,
				"fields": fields,
				"ts":     event.Timestamp.Unix(),
			},
		},
	}
	return json.Marshal(payload)
}

func (d *Dispatcher) sendDiscord(ctx context.Context, targetURL string, event Event) error {
	body, err := BuildDiscordPayload(event)
	if err != nil {
		return fmt.Errorf("failed to encode discord payload: %w", err)
	}
	return d.postWebhook(ctx, targetURL, body)
}

func (d *Dispatcher) sendSlack(ctx context.Context, targetURL string, event Event) error {
	body, err := BuildSlackPayload(event)
	if err != nil {
		return fmt.Errorf("failed to encode slack payload: %w", err)
	}
	return d.postWebhook(ctx, targetURL, body)
}

func (d *Dispatcher) postWebhook(ctx context.Context, targetURL string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Dock-Radar-AlertBot/1.0")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook endpoint returned status %d", resp.StatusCode)
	}
	return nil
}

func generateEventID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("evt_%s", hex.EncodeToString(b))
}
