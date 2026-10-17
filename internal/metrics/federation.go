package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/federation"
)

// AppendFederationMetrics formats multi-region edge federation and WAN sync telemetry into Prometheus exposition format.
func AppendFederationMetrics(builder *strings.Builder, status *federation.FederationStatus) {
	if status == nil {
		return
	}

	builder.WriteString("# HELP dock_radar_federation_regions_total Total registered edge federation regions\n")
	builder.WriteString("# TYPE dock_radar_federation_regions_total gauge\n")
	fmt.Fprintf(builder, "dock_radar_federation_regions_total %d\n", status.TotalRegions)

	builder.WriteString("# HELP dock_radar_federation_regions_healthy Current healthy online edge regions\n")
	builder.WriteString("# TYPE dock_radar_federation_regions_healthy gauge\n")
	fmt.Fprintf(builder, "dock_radar_federation_regions_healthy %d\n", status.HealthyRegions)

	builder.WriteString("# HELP dock_radar_federation_tunnels_active Active encrypted overlay tunnels\n")
	builder.WriteString("# TYPE dock_radar_federation_tunnels_active gauge\n")
	fmt.Fprintf(builder, "dock_radar_federation_tunnels_active %d\n", status.ActiveTunnels)

	builder.WriteString("# HELP dock_radar_federation_wan_sync_bytes_total Cumulative WAN payload bytes synchronized\n")
	builder.WriteString("# TYPE dock_radar_federation_wan_sync_bytes_total counter\n")
	fmt.Fprintf(builder, "dock_radar_federation_wan_sync_bytes_total %d\n", status.TotalSyncBytes)

	builder.WriteString("# HELP dock_radar_federation_wan_sync_saved_bytes_total Cumulative WAN bytes saved via delta compression\n")
	builder.WriteString("# TYPE dock_radar_federation_wan_sync_saved_bytes_total counter\n")
	fmt.Fprintf(builder, "dock_radar_federation_wan_sync_saved_bytes_total %d\n", status.TotalSavedBytes)

	builder.WriteString("# HELP dock_radar_federation_failover_events_total Cumulative traffic failover events\n")
	builder.WriteString("# TYPE dock_radar_federation_failover_events_total counter\n")
	fmt.Fprintf(builder, "dock_radar_federation_failover_events_total %d\n", status.FailoverCount)

	builder.WriteString("# HELP dock_radar_federation_enabled Federation status (1 if active, 0 otherwise)\n")
	builder.WriteString("# TYPE dock_radar_federation_enabled gauge\n")
	enabledVal := 0
	if status.Enabled {
		enabledVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_federation_enabled{local_region=\"%s\"} %d\n", status.LocalRegionID, enabledVal)
}
