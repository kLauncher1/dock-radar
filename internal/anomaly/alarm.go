package anomaly

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
)

// AlarmConfig configures the predictive out-of-memory threshold alarms and notifications.
type AlarmConfig struct {
	Enabled                bool          `json:"enabled"`
	WarningHorizonSeconds  int           `json:"warning_horizon_seconds"`
	CriticalHorizonSeconds int           `json:"critical_horizon_seconds"`
	CooldownDuration       time.Duration `json:"cooldown_duration"`
	DispatchWebhooks       bool          `json:"dispatch_webhooks"`
	MinRSquared            float64       `json:"min_r_squared"`
}

// DefaultAlarmConfig provides production default configurations for early warning alarms.
func DefaultAlarmConfig() AlarmConfig {
	return AlarmConfig{
		Enabled:                true,
		WarningHorizonSeconds:  300, // 5 minutes warning
		CriticalHorizonSeconds: 60,  // 1 minute critical
		CooldownDuration:       5 * time.Minute,
		DispatchWebhooks:       true,
		MinRSquared:            0.50,
	}
}

// AlarmEvent represents a triggered early-warning OOM alert incident.
type AlarmEvent struct {
	ID                    string    `json:"id"`
	ContainerID           string    `json:"container_id"`
	ContainerName         string    `json:"container_name"`
	Severity              string    `json:"severity"` // "warning" or "critical"
	PredictedSecondsToOOM float64   `json:"predicted_seconds_to_oom"`
	CurrentMemoryBytes    uint64    `json:"current_memory_bytes"`
	MemoryLimitBytes      uint64    `json:"memory_limit_bytes"`
	GrowthRateBytesPerSec float64   `json:"growth_rate_bytes_per_sec"`
	RSquared              float64   `json:"r_squared"`
	TriggeredAt           time.Time `json:"triggered_at"`
	Message               string    `json:"message"`
}

// AlarmManager manages cooldowns, event history, and early-warning webhook dispatches.
type AlarmManager struct {
	mu         sync.RWMutex
	config     AlarmConfig
	cooldowns  map[string]time.Time
	events     []AlarmEvent
	maxEvents  int
	eventHead  int
	eventCount int
}

// NewAlarmManager initializes an early warning alarm manager with bounded history.
func NewAlarmManager(cfg AlarmConfig, maxEvents int) *AlarmManager {
	if maxEvents <= 0 {
		maxEvents = 200
	}
	return &AlarmManager{
		config:    cfg,
		cooldowns: make(map[string]time.Time),
		events:    make([]AlarmEvent, maxEvents),
		maxEvents: maxEvents,
	}
}

// GetConfig returns a thread-safe copy of the current alarm configuration.
func (am *AlarmManager) GetConfig() AlarmConfig {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.config
}

// UpdateConfig updates the alarm policy parameters safely.
func (am *AlarmManager) UpdateConfig(cfg AlarmConfig) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if cfg.WarningHorizonSeconds <= 0 {
		cfg.WarningHorizonSeconds = 300
	}
	if cfg.CriticalHorizonSeconds <= 0 {
		cfg.CriticalHorizonSeconds = 60
	}
	if cfg.CooldownDuration < 10*time.Second {
		cfg.CooldownDuration = 10 * time.Second
	}
	if cfg.MinRSquared < 0.0 || cfg.MinRSquared > 1.0 {
		cfg.MinRSquared = 0.50
	}

	am.config = cfg
	return nil
}

// EvaluateAndDispatch evaluates a container trend prediction against alarm thresholds.
func (am *AlarmManager) EvaluateAndDispatch(pred TrendPrediction, dispatcher *alert.Dispatcher) *AlarmEvent {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.config.Enabled {
		return nil
	}

	// Must meet minimum correlation requirement to avoid alerting on noise
	if pred.RSquared < am.config.MinRSquared && pred.Category != ExhaustionCritical {
		return nil
	}

	severity := ""
	level := alert.LevelWarning
	if pred.Category == ExhaustionCritical {
		severity = "critical"
		level = alert.LevelCritical
	} else if pred.Category == ExhaustionWarning {
		severity = "warning"
		level = alert.LevelWarning
	} else {
		return nil
	}

	// Cooldown key per container and severity
	cdKey := fmt.Sprintf("%s:%s", pred.ContainerID, severity)
	now := time.Now().UTC()
	if lastTrigger, exists := am.cooldowns[cdKey]; exists {
		if now.Sub(lastTrigger) < am.config.CooldownDuration {
			return nil // Still within cooldown window
		}
	}

	am.cooldowns[cdKey] = now

	// Generate incident ID
	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)
	eventID := fmt.Sprintf("oom-%s", hex.EncodeToString(randBytes))

	currMB := float64(pred.CurrentMemoryBytes) / (1024 * 1024)
	limitMB := float64(pred.MemoryLimitBytes) / (1024 * 1024)
	growthMBs := pred.SlopeBytesPerSec / (1024 * 1024)

	var msg string
	if severity == "critical" {
		msg = fmt.Sprintf("CRITICAL: Container '%s' projected to hit OOM limit in %.1f seconds (Memory: %.1f MB / %.1f MB, Rate: +%.2f MB/s, R²: %.2f)",
			pred.ContainerName, pred.SecondsToOOM, currMB, limitMB, growthMBs, pred.RSquared)
	} else {
		msg = fmt.Sprintf("WARNING: Container '%s' rapid memory growth forecasting exhaustion in %.0f seconds (Memory: %.1f MB / %.1f MB, Rate: +%.2f MB/s, R²: %.2f)",
			pred.ContainerName, pred.SecondsToOOM, currMB, limitMB, growthMBs, pred.RSquared)
	}

	event := AlarmEvent{
		ID:                    eventID,
		ContainerID:           pred.ContainerID,
		ContainerName:         pred.ContainerName,
		Severity:              severity,
		PredictedSecondsToOOM: pred.SecondsToOOM,
		CurrentMemoryBytes:    pred.CurrentMemoryBytes,
		MemoryLimitBytes:      pred.MemoryLimitBytes,
		GrowthRateBytesPerSec: pred.SlopeBytesPerSec,
		RSquared:              pred.RSquared,
		TriggeredAt:           now,
		Message:               msg,
	}

	// Record in circular buffer
	am.events[am.eventHead] = event
	am.eventHead = (am.eventHead + 1) % am.maxEvents
	if am.eventCount < am.maxEvents {
		am.eventCount++
	}

	// Dispatch outbound webhook notifications if configured
	if am.config.DispatchWebhooks && dispatcher != nil {
		go func(e AlarmEvent, lvl string, text string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = dispatcher.Dispatch(ctx, alert.Event{
				ID:        e.ID,
				Timestamp: e.TriggeredAt,
				Level:     lvl,
				Source:    "anomaly_detector",
				EventType: "predictive_oom_alarm",
				Message:   text,
				Details: map[string]any{
					"container_id":     e.ContainerID,
					"container_name":   e.ContainerName,
					"seconds_to_oom":   e.PredictedSecondsToOOM,
					"growth_rate_mbs":  growthMBs,
					"current_mb":       currMB,
					"limit_mb":         limitMB,
					"r_squared":        e.RSquared,
					"predicted_action": "Recommend scaling container memory limit or graceful restart before OOM killer triggers.",
				},
			})
		}(event, level, msg)
	}

	return &event
}

// RecentEvents returns recent early-warning alert events in reverse chronological order.
func (am *AlarmManager) RecentEvents(limit int) []AlarmEvent {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if limit <= 0 || limit > am.eventCount {
		limit = am.eventCount
	}

	out := make([]AlarmEvent, limit)
	for i := 0; i < limit; i++ {
		idx := (am.eventHead - 1 - i + am.maxEvents) % am.maxEvents
		out[i] = am.events[idx]
	}
	return out
}

// Len returns the number of recorded alarm events.
func (am *AlarmManager) Len() int {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.eventCount
}
