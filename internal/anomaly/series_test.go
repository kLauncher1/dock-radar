package anomaly

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestContainerSeries_CircularBuffer(t *testing.T) {
	s := NewContainerSeries("c-1", "redis", 3)

	now := time.Now().UTC()
	s.Add(MetricSample{Timestamp: now, MemoryBytes: 100})
	s.Add(MetricSample{Timestamp: now.Add(1 * time.Second), MemoryBytes: 200})
	s.Add(MetricSample{Timestamp: now.Add(2 * time.Second), MemoryBytes: 300})

	if s.Count() != 3 {
		t.Fatalf("expected count 3, got %d", s.Count())
	}

	samples := s.Samples()
	if len(samples) != 3 {
		t.Fatalf("expected 3 samples, got %d", len(samples))
	}
	if samples[0].MemoryBytes != 100 || samples[2].MemoryBytes != 300 {
		t.Fatalf("unexpected chronological samples: %v", samples)
	}

	// Add 4th sample to trigger wrap-around
	s.Add(MetricSample{Timestamp: now.Add(3 * time.Second), MemoryBytes: 400})
	if s.Count() != 3 {
		t.Fatalf("expected count still 3, got %d", s.Count())
	}

	samples = s.Samples()
	if samples[0].MemoryBytes != 200 || samples[1].MemoryBytes != 300 || samples[2].MemoryBytes != 400 {
		t.Fatalf("wrap around failed, got %v", samples)
	}

	latest, ok := s.Latest()
	if !ok || latest.MemoryBytes != 400 {
		t.Fatalf("expected latest memory 400, got %v", latest)
	}
}

func TestTrackerStore_RecordAndPrune(t *testing.T) {
	ts := NewTrackerStore(5, 10)

	now := time.Now().UTC()
	ts.RecordMetric("c-1", "app-1", MetricSample{Timestamp: now, MemoryBytes: 100})
	ts.RecordMetric("c-2", "app-2", MetricSample{Timestamp: now.Add(-2 * time.Hour), MemoryBytes: 200})

	if ts.Len() != 2 {
		t.Fatalf("expected 2 series, got %d", ts.Len())
	}

	// Prune older than 1 hour
	pruned := ts.PruneStale(1 * time.Hour)
	if pruned != 1 {
		t.Fatalf("expected 1 pruned container, got %d", pruned)
	}
	if ts.Len() != 1 {
		t.Fatalf("expected 1 remaining series, got %d", ts.Len())
	}

	_, exists := ts.GetSeries("c-1")
	if !exists {
		t.Fatalf("expected c-1 to still exist")
	}
	_, exists = ts.GetSeries("c-2")
	if exists {
		t.Fatalf("expected c-2 to have been pruned")
	}
}

func TestTrackerStore_MaxCapacityEviction(t *testing.T) {
	ts := NewTrackerStore(3, 5)

	now := time.Now().UTC()
	ts.RecordMetric("c-1", "app-1", MetricSample{Timestamp: now.Add(-30 * time.Minute)})
	ts.RecordMetric("c-2", "app-2", MetricSample{Timestamp: now.Add(-20 * time.Minute)})
	ts.RecordMetric("c-3", "app-3", MetricSample{Timestamp: now.Add(-10 * time.Minute)})

	if ts.Len() != 3 {
		t.Fatalf("expected 3 series, got %d", ts.Len())
	}

	// Adding 4th should evict c-1 (the oldest)
	ts.RecordMetric("c-4", "app-4", MetricSample{Timestamp: now})
	if ts.Len() != 3 {
		t.Fatalf("expected 3 series after eviction, got %d", ts.Len())
	}

	if _, exists := ts.GetSeries("c-1"); exists {
		t.Fatalf("expected c-1 to be evicted as oldest")
	}
	if _, exists := ts.GetSeries("c-4"); !exists {
		t.Fatalf("expected c-4 to be recorded")
	}
}

func TestTrackerStore_Concurrency(t *testing.T) {
	ts := NewTrackerStore(100, 20)
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				cid := fmt.Sprintf("container-%d", (workerID*10+j)%15)
				ts.RecordMetric(cid, "worker", MetricSample{
					Timestamp:   time.Now().UTC(),
					MemoryBytes: uint64(workerID*1000 + j),
				})
			}
		}(i)
	}

	wg.Wait()
	if ts.Len() == 0 {
		t.Fatalf("expected containers to be tracked concurrently")
	}
}
