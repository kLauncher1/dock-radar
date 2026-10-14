package anomaly

import (
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
)

func TestAlarmManager_EvaluateAndDispatch(t *testing.T) {
	cfg := DefaultAlarmConfig()
	cfg.CooldownDuration = 100 * time.Millisecond
	am := NewAlarmManager(cfg, 50)

	cfgStore := alert.NewConfigStore(alert.Config{
		DiscordWebhookURL: "https://discord.com/api/webhooks/dummy/dummy",
	})
	dispatcher := alert.NewDispatcher(cfgStore)

	predCritical := TrendPrediction{
		ContainerID:        "c-oom-1",
		ContainerName:      "leaky-worker",
		CurrentMemoryBytes: 95000000,
		MemoryLimitBytes:   100000000,
		SlopeBytesPerSec:   1000000,
		RSquared:           0.95,
		SecondsToOOM:       5.0,
		Category:           ExhaustionCritical,
	}

	event := am.EvaluateAndDispatch(predCritical, dispatcher)
	if event == nil {
		t.Fatalf("expected alarm event to be generated for critical prediction")
	}
	if event.Severity != "critical" {
		t.Fatalf("expected severity 'critical', got '%s'", event.Severity)
	}
	if am.Len() != 1 {
		t.Fatalf("expected 1 recorded event, got %d", am.Len())
	}

	// Immediate re-evaluation should be blocked by cooldown
	dupEvent := am.EvaluateAndDispatch(predCritical, dispatcher)
	if dupEvent != nil {
		t.Fatalf("expected cooldown to suppress duplicate event, got %v", dupEvent)
	}

	// After cooldown window expires, next alert is allowed
	time.Sleep(120 * time.Millisecond)
	secondEvent := am.EvaluateAndDispatch(predCritical, dispatcher)
	if secondEvent == nil {
		t.Fatalf("expected event after cooldown expired")
	}
	if am.Len() != 2 {
		t.Fatalf("expected 2 recorded events, got %d", am.Len())
	}
}

func TestAlarmManager_StableIgnored(t *testing.T) {
	am := NewAlarmManager(DefaultAlarmConfig(), 50)
	predStable := TrendPrediction{
		ContainerID:   "c-stable",
		ContainerName: "stable-app",
		Category:      ExhaustionStable,
		SecondsToOOM:  -1.0,
	}

	event := am.EvaluateAndDispatch(predStable, nil)
	if event != nil {
		t.Fatalf("expected nil event for stable container, got %v", event)
	}
	if am.Len() != 0 {
		t.Fatalf("expected 0 events, got %d", am.Len())
	}
}

func TestAlarmManager_RecentEvents(t *testing.T) {
	am := NewAlarmManager(DefaultAlarmConfig(), 10)
	am.config.CooldownDuration = time.Millisecond

	for i := 0; i < 5; i++ {
		pred := TrendPrediction{
			ContainerID:        "c-test",
			ContainerName:      "test",
			CurrentMemoryBytes: 90000000,
			MemoryLimitBytes:   100000000,
			SlopeBytesPerSec:   500000,
			RSquared:           0.9,
			SecondsToOOM:       20.0,
			Category:           ExhaustionCritical,
		}
		am.EvaluateAndDispatch(pred, nil)
		time.Sleep(2 * time.Millisecond)
	}

	recent := am.RecentEvents(3)
	if len(recent) != 3 {
		t.Fatalf("expected 3 recent events, got %d", len(recent))
	}
}
