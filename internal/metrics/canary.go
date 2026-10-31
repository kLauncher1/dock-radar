package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/canary"
)

// AppendCanaryMetrics formats Autonomous Canary & Traffic Mirroring telemetry into standard Prometheus exposition format.
func AppendCanaryMetrics(builder *strings.Builder, status *canary.CanaryStatus, deployments []*canary.CanaryDeployment) {
	if status == nil {
		return
	}

	builder.WriteString("# HELP dock_radar_canary_enabled Whether the autonomous canary deployment engine is enabled (1 or 0)\n")
	builder.WriteString("# TYPE dock_radar_canary_enabled gauge\n")
	enabledVal := 0
	if status.Enabled {
		enabledVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_canary_enabled %d\n", enabledVal)

	builder.WriteString("# HELP dock_radar_canary_active_deployments Number of actively evaluating or promoting canary rollouts\n")
	builder.WriteString("# TYPE dock_radar_canary_active_deployments gauge\n")
	fmt.Fprintf(builder, "dock_radar_canary_active_deployments %d\n", status.ActiveDeployments)

	builder.WriteString("# HELP dock_radar_canary_total_deployments Total number of registered canary deployments\n")
	builder.WriteString("# TYPE dock_radar_canary_total_deployments gauge\n")
	fmt.Fprintf(builder, "dock_radar_canary_total_deployments %d\n", status.TotalDeployments)

	builder.WriteString("# HELP dock_radar_canary_requests_routed_total Cumulative requests routed through the canary splitter\n")
	builder.WriteString("# TYPE dock_radar_canary_requests_routed_total counter\n")
	fmt.Fprintf(builder, "dock_radar_canary_requests_routed_total %d\n", status.TotalRoutedReqs)

	builder.WriteString("# HELP dock_radar_canary_requests_mirrored_total Cumulative requests mirrored to shadow targets\n")
	builder.WriteString("# TYPE dock_radar_canary_requests_mirrored_total counter\n")
	fmt.Fprintf(builder, "dock_radar_canary_requests_mirrored_total %d\n", status.TotalMirroredReqs)

	builder.WriteString("# HELP dock_radar_canary_rollbacks_total Cumulative autonomous rollbacks triggered by divergence\n")
	builder.WriteString("# TYPE dock_radar_canary_rollbacks_total counter\n")
	fmt.Fprintf(builder, "dock_radar_canary_rollbacks_total %d\n", status.TotalRollbacks)

	if len(deployments) > 0 {
		builder.WriteString("# HELP dock_radar_canary_traffic_weight Percentage of traffic routed to targets\n")
		builder.WriteString("# TYPE dock_radar_canary_traffic_weight gauge\n")
		for _, dep := range deployments {
			if dep == nil {
				continue
			}
			depLabel := escapeLabel(dep.ID)
			fmt.Fprintf(builder, "dock_radar_canary_traffic_weight{deployment=\"%s\",target=\"canary\"} %d\n", depLabel, dep.Traffic.CanaryWeight)
			fmt.Fprintf(builder, "dock_radar_canary_traffic_weight{deployment=\"%s\",target=\"baseline\"} %d\n", depLabel, dep.Traffic.BaselineWeight)
		}
	}
	builder.WriteString("\n")
}
