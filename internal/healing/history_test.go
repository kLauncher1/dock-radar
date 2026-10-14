package healing

import (
	"sync"
	"testing"
	"time"
)

func TestHistoryBuffer_BasicAndWrapAround(t *testing.T) {
	buf := NewHistoryBuffer(3)

	events := []RemediationEvent{
		{ContainerID: "c1", ContainerName: "web", Trigger: "oom_killed", Action: "restart"},
		{ContainerID: "c2", ContainerName: "db", Trigger: "crash_loop", Action: "restart"},
		{ContainerID: "c3", ContainerName: "cache", Trigger: "healthcheck_failed", Action: "restart"},
		{ContainerID: "c4", ContainerName: "worker", Trigger: "oom_killed", Action: "quarantine"},
	}

	for _, e := range events {
		buf.Record(e)
	}

	if buf.Len() != 3 {
		t.Fatalf("Expected buffer length 3, got %d", buf.Len())
	}
	if buf.TotalCount() != 4 {
		t.Fatalf("Expected total count 4, got %d", buf.TotalCount())
	}

	recent := buf.Recent(10, "", "")
	if len(recent) != 3 {
		t.Fatalf("Expected 3 items from Recent(), got %d", len(recent))
	}

	// First recent item should be the newest (c4)
	if recent[0].ContainerID != "c4" {
		t.Errorf("Expected newest item to be c4, got %s", recent[0].ContainerID)
	}
	if recent[2].ContainerID != "c2" {
		t.Errorf("Expected oldest retained item to be c2, got %s", recent[2].ContainerID)
	}
}

func TestHistoryBuffer_Filtering(t *testing.T) {
	buf := NewHistoryBuffer(10)

	buf.Record(RemediationEvent{ContainerID: "c1", ContainerName: "nginx-proxy", Trigger: "oom_killed"})
	buf.Record(RemediationEvent{ContainerID: "c2", ContainerName: "postgres-db", Trigger: "crash_loop"})
	buf.Record(RemediationEvent{ContainerID: "c1", ContainerName: "nginx-proxy", Trigger: "healthcheck_failed"})

	byContainer := buf.Recent(10, "nginx", "")
	if len(byContainer) != 2 {
		t.Errorf("Expected 2 events for nginx, got %d", len(byContainer))
	}

	byTrigger := buf.Recent(10, "", "crash_loop")
	if len(byTrigger) != 1 {
		t.Errorf("Expected 1 event for crash_loop, got %d", len(byTrigger))
	}
}

func TestHistoryBuffer_Concurrency(t *testing.T) {
	buf := NewHistoryBuffer(100)
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(id int) {
			defer wg.Done()
			buf.Record(RemediationEvent{
				ContainerID: "test-c",
				Timestamp:   time.Now().UTC(),
				Trigger:     "oom_killed",
			})
		}(i)

		go func() {
			defer wg.Done()
			_ = buf.Recent(10, "", "")
		}()
	}

	wg.Wait()

	if buf.TotalCount() != 20 {
		t.Errorf("Expected 20 total recorded events, got %d", buf.TotalCount())
	}
}
