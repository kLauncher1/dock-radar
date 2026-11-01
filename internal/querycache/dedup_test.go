package querycache

import (
	"fmt"
	"testing"
	"time"
)

func TestDedup_BasicDetection(t *testing.T) {
	cfg := DefaultDedupConfig()
	d := NewEventDeduplicator(cfg)

	ev := DockerEvent{
		ID:        "evt-12345",
		Type:      "container",
		Action:    "die",
		ActorID:   "c-app",
		Time:      time.Now().Unix(),
	}

	// First time: unique
	if d.IsDuplicate(ev) {
		t.Fatal("first encounter should not be marked as duplicate")
	}

	// Second time: duplicate
	if !d.IsDuplicate(ev) {
		t.Fatal("immediate second encounter should be marked as duplicate")
	}

	stats := d.Stats()
	if stats.TotalChecked != 2 {
		t.Errorf("expected 2 checked, got %d", stats.TotalChecked)
	}
	if stats.TotalUnique != 1 {
		t.Errorf("expected 1 unique, got %d", stats.TotalUnique)
	}
	if stats.TotalDeduped != 1 {
		t.Errorf("expected 1 deduped, got %d", stats.TotalDeduped)
	}
}

func TestDedup_WindowExpiration(t *testing.T) {
	cfg := DefaultDedupConfig()
	cfg.Window = 20 * time.Millisecond
	d := NewEventDeduplicator(cfg)

	ev := DockerEvent{
		ID:      "evt-expiring",
		Action:  "start",
		ActorID: "c-short",
	}

	if d.IsDuplicate(ev) {
		t.Fatal("initial event should be unique")
	}

	time.Sleep(30 * time.Millisecond)

	// After window expires, should be treated as new event
	if d.IsDuplicate(ev) {
		t.Fatal("event after window expiration should not be duplicate")
	}
}

func TestDedup_CapacityEviction(t *testing.T) {
	cfg := DefaultDedupConfig()
	cfg.MaxTracked = 3
	cfg.Window = 1 * time.Minute
	d := NewEventDeduplicator(cfg)

	for i := 1; i <= 5; i++ {
		ev := DockerEvent{
			ID:      fmt.Sprintf("evt-%d", i),
			Action:  "ping",
			ActorID: "node",
		}
		_ = d.IsDuplicate(ev)
	}

	stats := d.Stats()
	if stats.ActiveTracked > 3 {
		t.Errorf("expected active tracked <= 3, got %d", stats.ActiveTracked)
	}
}

func TestDedup_ResetAndStats(t *testing.T) {
	cfg := DefaultDedupConfig()
	d := NewEventDeduplicator(cfg)

	_ = d.IsDuplicate(DockerEvent{ID: "e1", Action: "a1", ActorID: "c1"})
	_ = d.IsDuplicate(DockerEvent{ID: "e1", Action: "a1", ActorID: "c1"})

	statsBefore := d.Stats()
	if statsBefore.TotalDeduped != 1 {
		t.Errorf("expected 1 deduped before reset, got %d", statsBefore.TotalDeduped)
	}

	d.Reset()

	statsAfter := d.Stats()
	if statsAfter.TotalChecked != 0 || statsAfter.TotalDeduped != 0 || statsAfter.ActiveTracked != 0 {
		t.Errorf("expected zeroed stats after reset, got %+v", statsAfter)
	}
}
