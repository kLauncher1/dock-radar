package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/querycache"
)

// AppendQueryCacheMetrics formats Self-Optimizing Query Cache & Event Pipeline telemetry into Prometheus exposition format.
func AppendQueryCacheMetrics(builder *strings.Builder, status *querycache.QueryCacheStatus) {
	if status == nil {
		return
	}

	builder.WriteString("# HELP dock_radar_querycache_enabled Whether the query cache is enabled (1 or 0)\n")
	builder.WriteString("# TYPE dock_radar_querycache_enabled gauge\n")
	enabledVal := 0
	if status.Enabled {
		enabledVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_querycache_enabled %d\n", enabledVal)

	builder.WriteString("# HELP dock_radar_querycache_hits_total Total number of query cache hits\n")
	builder.WriteString("# TYPE dock_radar_querycache_hits_total counter\n")
	fmt.Fprintf(builder, "dock_radar_querycache_hits_total %d\n", status.Cache.TotalHits)

	builder.WriteString("# HELP dock_radar_querycache_misses_total Total number of query cache misses\n")
	builder.WriteString("# TYPE dock_radar_querycache_misses_total counter\n")
	fmt.Fprintf(builder, "dock_radar_querycache_misses_total %d\n", status.Cache.TotalMisses)

	builder.WriteString("# HELP dock_radar_querycache_hit_ratio Percentage of query cache requests served from cache\n")
	builder.WriteString("# TYPE dock_radar_querycache_hit_ratio gauge\n")
	fmt.Fprintf(builder, "dock_radar_querycache_hit_ratio %.2f\n", status.Cache.HitRatio)

	builder.WriteString("# HELP dock_radar_querycache_items Total number of active cached items in memory\n")
	builder.WriteString("# TYPE dock_radar_querycache_items gauge\n")
	fmt.Fprintf(builder, "dock_radar_querycache_items %d\n", status.Cache.ItemCount)

	builder.WriteString("# HELP dock_radar_querycache_bytes Approximate memory consumption of query cache in bytes\n")
	builder.WriteString("# TYPE dock_radar_querycache_bytes gauge\n")
	fmt.Fprintf(builder, "dock_radar_querycache_bytes %d\n", status.Cache.MemoryBytes)

	builder.WriteString("# HELP dock_radar_querycache_evictions_total Cumulative items evicted due to TTL or capacity limits\n")
	builder.WriteString("# TYPE dock_radar_querycache_evictions_total counter\n")
	fmt.Fprintf(builder, "dock_radar_querycache_evictions_total %d\n", status.Cache.EvictionsTotal)

	builder.WriteString("# HELP dock_radar_querycache_coalesced_total Coalesced in-flight duplicate computations to prevent thundering herd\n")
	builder.WriteString("# TYPE dock_radar_querycache_coalesced_total counter\n")
	fmt.Fprintf(builder, "dock_radar_querycache_coalesced_total %d\n", status.Cache.CoalescedCalls)

	builder.WriteString("# HELP dock_radar_event_multiplexer_subscribers Current active event multiplexer listeners\n")
	builder.WriteString("# TYPE dock_radar_event_multiplexer_subscribers gauge\n")
	fmt.Fprintf(builder, "dock_radar_event_multiplexer_subscribers %d\n", status.Multiplexer.ActiveSubscribers)

	builder.WriteString("# HELP dock_radar_event_multiplexer_ingested_total Cumulative events ingested by the event pipeline\n")
	builder.WriteString("# TYPE dock_radar_event_multiplexer_ingested_total counter\n")
	fmt.Fprintf(builder, "dock_radar_event_multiplexer_ingested_total %d\n", status.Multiplexer.TotalIngested)

	builder.WriteString("# HELP dock_radar_event_multiplexer_dropped_total Events dropped due to slow subscriber backpressure buffer limits\n")
	builder.WriteString("# TYPE dock_radar_event_multiplexer_dropped_total counter\n")
	fmt.Fprintf(builder, "dock_radar_event_multiplexer_dropped_total %d\n", status.Multiplexer.TotalDropped)

	builder.WriteString("# HELP dock_radar_event_dedup_deduped_total Duplicate events suppressed by sliding-window deduplication\n")
	builder.WriteString("# TYPE dock_radar_event_dedup_deduped_total counter\n")
	fmt.Fprintf(builder, "dock_radar_event_dedup_deduped_total %d\n", status.Deduplicator.TotalDeduped)

	builder.WriteString("\n")
}
