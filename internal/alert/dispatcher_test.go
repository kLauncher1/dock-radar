package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBuildDiscordPayload(t *testing.T) {
	now := time.Now().UTC()
	event := Event{
		ID:        "evt_1",
		Timestamp: now,
		Level:     LevelCritical,
		Source:    "container:nginx",
		EventType: "container_exit",
		Message:   "Container terminated abnormally",
		Details:   map[string]any{"exit_code": 137},
	}

	payloadBytes, err := BuildDiscordPayload(event)
	if err != nil {
		t.Fatalf("failed to build discord payload: %v", err)
	}

	var data map[string]any
	if err := json.Unmarshal(payloadBytes, &data); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}

	embeds, ok := data["embeds"].([]any)
	if !ok || len(embeds) != 1 {
		t.Fatalf("expected 1 embed object")
	}

	embed := embeds[0].(map[string]any)
	if embed["color"].(float64) != 15158332 {
		t.Errorf("expected red color 15158332 for critical, got %v", embed["color"])
	}
	if embed["description"] != event.Message {
		t.Errorf("expected description %q, got %v", event.Message, embed["description"])
	}

	// Test warning level color
	event.Level = LevelWarning
	wBytes, _ := BuildDiscordPayload(event)
	var wData map[string]any
	_ = json.Unmarshal(wBytes, &wData)
	wEmbed := wData["embeds"].([]any)[0].(map[string]any)
	if wEmbed["color"].(float64) != 15105570 {
		t.Errorf("expected orange color 15105570 for warning, got %v", wEmbed["color"])
	}

	// Test info level color
	event.Level = LevelInfo
	iBytes, _ := BuildDiscordPayload(event)
	var iData map[string]any
	_ = json.Unmarshal(iBytes, &iData)
	iEmbed := iData["embeds"].([]any)[0].(map[string]any)
	if iEmbed["color"].(float64) != 3066993 {
		t.Errorf("expected green color 3066993 for info, got %v", iEmbed["color"])
	}
}

func TestBuildSlackPayload(t *testing.T) {
	now := time.Now().UTC()
	event := Event{
		ID:        "evt_2",
		Timestamp: now,
		Level:     LevelCritical,
		Source:    "system:host",
		EventType: "memory_threshold",
		Message:   "Host memory allocation high",
	}

	payloadBytes, err := BuildSlackPayload(event)
	if err != nil {
		t.Fatalf("failed to build slack payload: %v", err)
	}

	var data map[string]any
	if err := json.Unmarshal(payloadBytes, &data); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}

	attachments, ok := data["attachments"].([]any)
	if !ok || len(attachments) != 1 {
		t.Fatalf("expected 1 attachment")
	}

	att := attachments[0].(map[string]any)
	if att["color"] != "#e74c3c" {
		t.Errorf("expected color #e74c3c for critical, got %v", att["color"])
	}

	// Test warning color
	event.Level = LevelWarning
	wBytes, _ := BuildSlackPayload(event)
	var wData map[string]any
	_ = json.Unmarshal(wBytes, &wData)
	wAtt := wData["attachments"].([]any)[0].(map[string]any)
	if wAtt["color"] != "#e67e22" {
		t.Errorf("expected color #e67e22 for warning, got %v", wAtt["color"])
	}
}

func TestDispatcher_EventBuffer(t *testing.T) {
	store := NewConfigStore(DefaultConfig())
	dispatcher := NewDispatcher(store)

	for i := 0; i < 120; i++ {
		dispatcher.RecordEvent(Event{
			ID:      "evt",
			Message: "test message",
		})
	}

	recent := dispatcher.RecentEvents(50)
	if len(recent) != 50 {
		t.Fatalf("expected 50 recent events, got %d", len(recent))
	}

	all := dispatcher.RecentEvents(200)
	if len(all) != 100 {
		t.Fatalf("expected buffer to cap at 100, got %d", len(all))
	}
}

func TestDispatcher_DispatchAndCooldown(t *testing.T) {
	var callCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := NewConfigStore(DefaultConfig())
	_ = store.Update(Config{
		Enabled:               true,
		DiscordWebhookURL:     server.URL,
		SlackWebhookURL:       "",
		CooldownSeconds:       10,
		CPUThresholdPercent:   85,
		MemoryThresholdMB:     500,
		RestartThresholdCount: 3,
		FlappingWindowSeconds: 300,
	})

	dispatcher := NewDispatcherWithClient(store, server.Client())
	ctx := context.Background()

	evt := Event{
		Source:    "container:redis",
		EventType: "container_exit",
		Level:     LevelCritical,
		Message:   "Redis container died",
	}

	// 1. First dispatch -> must trigger webhook
	if err := dispatcher.Dispatch(ctx, evt); err != nil {
		t.Fatalf("unexpected dispatch error: %v", err)
	}
	if atomic.LoadInt32(&callCount) != 1 {
		t.Fatalf("expected 1 call, got %d", atomic.LoadInt32(&callCount))
	}

	// 2. Immediate second dispatch with same source & eventType -> must be suppressed by cooldown
	if err := dispatcher.Dispatch(ctx, evt); err != nil {
		t.Fatalf("unexpected error during cooldown dispatch: %v", err)
	}
	if atomic.LoadInt32(&callCount) != 1 {
		t.Fatalf("expected still 1 call due to cooldown suppression, got %d", atomic.LoadInt32(&callCount))
	}

	// 3. Different source -> must trigger webhook
	evt2 := Event{
		Source:    "container:postgres",
		EventType: "container_exit",
		Level:     LevelCritical,
		Message:   "Postgres container died",
	}
	if err := dispatcher.Dispatch(ctx, evt2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&callCount) != 2 {
		t.Fatalf("expected 2 calls, got %d", atomic.LoadInt32(&callCount))
	}
}

func TestDispatcher_SendTestNotification(t *testing.T) {
	var discordCalls int32
	var slackCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/discord" {
			atomic.AddInt32(&discordCalls, 1)
		} else if r.URL.Path == "/slack" {
			atomic.AddInt32(&slackCalls, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := NewConfigStore(DefaultConfig())
	_ = store.Update(Config{
		Enabled:               false, // Test notifications work even if monitoring loop is disabled
		DiscordWebhookURL:     server.URL + "/discord",
		SlackWebhookURL:       server.URL + "/slack",
		CooldownSeconds:       60,
		CPUThresholdPercent:   85,
		MemoryThresholdMB:     500,
		RestartThresholdCount: 3,
		FlappingWindowSeconds: 300,
	})

	dispatcher := NewDispatcherWithClient(store, server.Client())
	ctx := context.Background()

	// Test Discord specific
	if err := dispatcher.SendTestNotification(ctx, "discord"); err != nil {
		t.Fatalf("unexpected discord test error: %v", err)
	}
	if atomic.LoadInt32(&discordCalls) != 1 || atomic.LoadInt32(&slackCalls) != 0 {
		t.Fatalf("expected 1 discord call, 0 slack calls")
	}

	// Test Slack specific
	if err := dispatcher.SendTestNotification(ctx, "slack"); err != nil {
		t.Fatalf("unexpected slack test error: %v", err)
	}
	if atomic.LoadInt32(&discordCalls) != 1 || atomic.LoadInt32(&slackCalls) != 1 {
		t.Fatalf("expected 1 discord call, 1 slack call")
	}

	// Test all
	if err := dispatcher.SendTestNotification(ctx, "all"); err != nil {
		t.Fatalf("unexpected all test error: %v", err)
	}
	if atomic.LoadInt32(&discordCalls) != 2 || atomic.LoadInt32(&slackCalls) != 2 {
		t.Fatalf("expected 2 discord calls, 2 slack calls")
	}
}
