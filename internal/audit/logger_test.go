package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLogger_BasicAndDefaults(t *testing.T) {
	logger := NewLogger(10)
	if logger.Capacity() != 10 {
		t.Fatalf("expected capacity 10, got %d", logger.Capacity())
	}

	ev := logger.Log(AuditEvent{
		Action: "container_restart",
		Target: "redis-cache",
	})

	if ev.ID == "" || !strings.HasPrefix(ev.ID, "aud_") {
		t.Errorf("expected auto-generated ID with prefix aud_, got %s", ev.ID)
	}
	if ev.Timestamp.IsZero() {
		t.Errorf("expected non-zero timestamp")
	}
	if ev.Actor != "system" {
		t.Errorf("expected default actor 'system', got %s", ev.Actor)
	}
	if ev.ClientIP != "127.0.0.1" {
		t.Errorf("expected default client IP '127.0.0.1', got %s", ev.ClientIP)
	}
	if ev.Status != "success" {
		t.Errorf("expected default status 'success', got %s", ev.Status)
	}

	if logger.Len() != 1 {
		t.Errorf("expected buffer len 1, got %d", logger.Len())
	}
	if logger.TotalCount() != 1 {
		t.Errorf("expected total count 1, got %d", logger.TotalCount())
	}
}

func TestLogger_WrapAround(t *testing.T) {
	logger := NewLogger(3)

	for i := 1; i <= 5; i++ {
		logger.Log(AuditEvent{
			ID:     fmt.Sprintf("evt-%d", i),
			Action: "restart",
			Target: fmt.Sprintf("target-%d", i),
		})
	}

	if logger.Len() != 3 {
		t.Fatalf("expected len 3, got %d", logger.Len())
	}
	if logger.TotalCount() != 5 {
		t.Fatalf("expected total count 5, got %d", logger.TotalCount())
	}

	recent := logger.Recent(10, "")
	if len(recent) != 3 {
		t.Fatalf("expected 3 recent events, got %d", len(recent))
	}

	expectedIDs := []string{"evt-3", "evt-4", "evt-5"}
	for i, want := range expectedIDs {
		if recent[i].ID != want {
			t.Errorf("at index %d: expected %s, got %s", i, want, recent[i].ID)
		}
	}
}

func TestLogger_ActionFilter(t *testing.T) {
	logger := NewLogger(10)

	logger.Log(AuditEvent{ID: "1", Action: "batch_restart", Target: "all"})
	logger.Log(AuditEvent{ID: "2", Action: "batch_stop", Target: "all"})
	logger.Log(AuditEvent{ID: "3", Action: "batch_restart", Target: "c1"})
	logger.Log(AuditEvent{ID: "4", Action: "batch_prune", Target: "unused"})
	logger.Log(AuditEvent{ID: "5", Action: "batch_restart", Target: "c2"})

	restarts := logger.Recent(10, "batch_restart")
	if len(restarts) != 3 {
		t.Fatalf("expected 3 restart events, got %d", len(restarts))
	}
	if restarts[0].ID != "1" || restarts[1].ID != "3" || restarts[2].ID != "5" {
		t.Errorf("unexpected restart order: %+v", restarts)
	}

	// Limit test with filter
	limitedRestarts := logger.Recent(2, "batch_restart")
	if len(limitedRestarts) != 2 {
		t.Fatalf("expected 2 restart events, got %d", len(limitedRestarts))
	}
	// Should be the latest 2 in chronological order: "3" and "5"
	if limitedRestarts[0].ID != "3" || limitedRestarts[1].ID != "5" {
		t.Errorf("expected latest 2 restarts to be 3 and 5, got %+v", limitedRestarts)
	}

	// "all" filter
	allEvents := logger.Recent(10, "all")
	if len(allEvents) != 5 {
		t.Fatalf("expected 5 events for 'all' filter, got %d", len(allEvents))
	}
}

func TestLogger_ExportNDJSON(t *testing.T) {
	logger := NewLogger(10)

	logger.Log(AuditEvent{
		ID:        "aud-1",
		Timestamp: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC),
		Actor:     "admin",
		ClientIP:  "192.168.1.10",
		Action:    "batch_restart_all",
		Target:    "all_containers",
		Status:    "success",
		Details:   map[string]any{"restarted": 3},
	})
	logger.Log(AuditEvent{
		ID:        "aud-2",
		Timestamp: time.Date(2026, 10, 14, 12, 1, 0, 0, time.UTC),
		Actor:     "admin",
		ClientIP:  "192.168.1.10",
		Action:    "batch_prune",
		Target:    "inactive",
		Status:    "success",
		Details:   map[string]any{"deleted": 2},
	})

	var buf bytes.Buffer
	err := logger.ExportNDJSON(&buf, 10, "")
	if err != nil {
		t.Fatalf("ExportNDJSON failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d: %s", len(lines), buf.String())
	}

	var ev1, ev2 AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &ev1); err != nil {
		t.Fatalf("failed to decode line 1: %v", err)
	}
	if ev1.ID != "aud-1" || ev1.Action != "batch_restart_all" {
		t.Errorf("unexpected ev1: %+v", ev1)
	}

	if err := json.Unmarshal([]byte(lines[1]), &ev2); err != nil {
		t.Fatalf("failed to decode line 2: %v", err)
	}
	if ev2.ID != "aud-2" || ev2.Action != "batch_prune" {
		t.Errorf("unexpected ev2: %+v", ev2)
	}
}

func TestLogger_Concurrency(t *testing.T) {
	logger := NewLogger(50)
	var wg sync.WaitGroup
	workers := 10
	iterations := 100

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				logger.Log(AuditEvent{
					Actor:   fmt.Sprintf("worker-%d", workerID),
					Action:  "batch_action",
					Target:  fmt.Sprintf("target-%d", i),
					Details: map[string]any{"seq": i},
				})

				if i%10 == 0 {
					_ = logger.Recent(5, "")
					var buf bytes.Buffer
					_ = logger.ExportNDJSON(&buf, 5, "")
				}
			}
		}(w)
	}

	wg.Wait()

	if logger.TotalCount() != int64(workers*iterations) {
		t.Errorf("expected total count %d, got %d", workers*iterations, logger.TotalCount())
	}
	if logger.Len() != 50 {
		t.Errorf("expected len capped at 50, got %d", logger.Len())
	}
}

func TestLogger_Clear(t *testing.T) {
	logger := NewLogger(10)
	logger.Log(AuditEvent{Action: "test"})
	if logger.Len() != 1 {
		t.Fatalf("expected len 1, got %d", logger.Len())
	}
	logger.Clear()
	if logger.Len() != 0 {
		t.Fatalf("expected len 0 after clear, got %d", logger.Len())
	}
	if len(logger.Recent(10, "")) != 0 {
		t.Fatalf("expected 0 recent events after clear")
	}
}
