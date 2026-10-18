package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/ratelimit"
)

// AppendRateLimitMetrics formats distributed rate limiter and IP abuse mitigation telemetry into Prometheus exposition format.
func AppendRateLimitMetrics(builder *strings.Builder, status *ratelimit.LimiterStatus) {
	if status == nil {
		return
	}

	builder.WriteString("# HELP dock_radar_ratelimit_enabled Distributed rate limiter status (1 if active, 0 otherwise)\n")
	builder.WriteString("# TYPE dock_radar_ratelimit_enabled gauge\n")
	enabledVal := 0
	if status.Enabled {
		enabledVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_ratelimit_enabled %d\n", enabledVal)

	builder.WriteString("# HELP dock_radar_ratelimit_tenants_total Total configured tenant quota profiles\n")
	builder.WriteString("# TYPE dock_radar_ratelimit_tenants_total gauge\n")
	fmt.Fprintf(builder, "dock_radar_ratelimit_tenants_total %d\n", status.TotalTenants)

	builder.WriteString("# HELP dock_radar_ratelimit_banned_ips_active Number of currently active IP bans\n")
	builder.WriteString("# TYPE dock_radar_ratelimit_banned_ips_active gauge\n")
	fmt.Fprintf(builder, "dock_radar_ratelimit_banned_ips_active %d\n", status.ActiveBannedIPs)

	builder.WriteString("# HELP dock_radar_ratelimit_evaluations_total Cumulative requests evaluated by rate limiting engine\n")
	builder.WriteString("# TYPE dock_radar_ratelimit_evaluations_total counter\n")
	fmt.Fprintf(builder, "dock_radar_ratelimit_evaluations_total %d\n", status.TotalEvaluations)

	builder.WriteString("# HELP dock_radar_ratelimit_throttled_total Cumulative requests throttled due to token exhaustion\n")
	builder.WriteString("# TYPE dock_radar_ratelimit_throttled_total counter\n")
	fmt.Fprintf(builder, "dock_radar_ratelimit_throttled_total %d\n", status.TotalThrottledRequests)

	builder.WriteString("# HELP dock_radar_ratelimit_banned_rejections_total Cumulative requests rejected due to active IP ban\n")
	builder.WriteString("# TYPE dock_radar_ratelimit_banned_rejections_total counter\n")
	fmt.Fprintf(builder, "dock_radar_ratelimit_banned_rejections_total %d\n", status.TotalBannedRejections)

	builder.WriteString("# HELP dock_radar_ratelimit_bandwidth_throttled_total Cumulative requests throttled due to bandwidth limit\n")
	builder.WriteString("# TYPE dock_radar_ratelimit_bandwidth_throttled_total counter\n")
	fmt.Fprintf(builder, "dock_radar_ratelimit_bandwidth_throttled_total %d\n", status.TotalBandwidthThrottled)

	builder.WriteString("# HELP dock_radar_ratelimit_synced_peers_count Count of cluster mesh peers synchronized for rate limits\n")
	builder.WriteString("# TYPE dock_radar_ratelimit_synced_peers_count gauge\n")
	fmt.Fprintf(builder, "dock_radar_ratelimit_synced_peers_count %d\n", status.SyncedPeersCount)
}
