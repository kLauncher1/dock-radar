package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/querycache"
)

func TestAppendQueryCacheMetrics(t *testing.T) {
	status := &querycache.QueryCacheStatus{
		Enabled: true,
		Cache: querycache.CacheStats{
			TotalHits:      150,
			TotalMisses:    50,
			HitRatio:       75.0,
			ItemCount:      42,
			MemoryBytes:    1048576,
			EvictionsTotal: 5,
			CoalescedCalls: 12,
		},
		Multiplexer: querycache.MultiplexerStats{
			ActiveSubscribers: 3,
			TotalIngested:     500,
			TotalDispatched:   495,
			TotalDropped:      5,
			QueueDepth:        10,
		},
		Deduplicator: querycache.DedupStats{
			TotalChecked:  500,
			TotalDeduped:  30,
			TotalUnique:   470,
			ActiveTracked: 120,
		},
		Timestamp: time.Now().UTC(),
	}

	var b strings.Builder
	AppendQueryCacheMetrics(&b, status)

	out := b.String()
	expectedMetrics := []string{
		"dock_radar_querycache_enabled 1",
		"dock_radar_querycache_hits_total 150",
		"dock_radar_querycache_misses_total 50",
		"dock_radar_querycache_hit_ratio 75.00",
		"dock_radar_querycache_items 42",
		"dock_radar_querycache_bytes 1048576",
		"dock_radar_querycache_evictions_total 5",
		"dock_radar_querycache_coalesced_total 12",
		"dock_radar_event_multiplexer_subscribers 3",
		"dock_radar_event_multiplexer_ingested_total 500",
		"dock_radar_event_multiplexer_dropped_total 5",
		"dock_radar_event_dedup_deduped_total 30",
	}

	for _, expected := range expectedMetrics {
		if !strings.Contains(out, expected) {
			t.Errorf("expected output to contain %q, but was missing. Full output:\n%s", expected, out)
		}
	}
}

func TestAppendQueryCacheMetrics_Nil(t *testing.T) {
	var b strings.Builder
	AppendQueryCacheMetrics(&b, nil)
	if b.Len() != 0 {
		t.Errorf("expected empty string for nil status, got %d bytes", b.Len())
	}
}
