package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/rolling"
)

// AppendRollingMetrics formats zero-downtime rolling restart telemetry into standard Prometheus text format.
func AppendRollingMetrics(b *strings.Builder, stats *rolling.RollingStats) {
	if stats == nil {
		return
	}

	b.WriteString("# HELP dock_radar_rolling_operations_total Cumulative total of rolling restart operations initiated.\n")
	b.WriteString("# TYPE dock_radar_rolling_operations_total counter\n")
	b.WriteString(fmt.Sprintf("dock_radar_rolling_operations_total %d\n\n", stats.TotalOperations))

	b.WriteString("# HELP dock_radar_rolling_operations_active Currently running rolling restart operations in flight.\n")
	b.WriteString("# TYPE dock_radar_rolling_operations_active gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_rolling_operations_active %d\n\n", stats.ActiveOperations))

	b.WriteString("# HELP dock_radar_rolling_containers_restarted_total Total containers successfully drained, restarted, and probed healthy.\n")
	b.WriteString("# TYPE dock_radar_rolling_containers_restarted_total counter\n")
	b.WriteString(fmt.Sprintf("dock_radar_rolling_containers_restarted_total %d\n\n", stats.TotalContainersRestarted))

	b.WriteString("# HELP dock_radar_rolling_containers_failed_total Total containers that failed readiness probing during rolling restart.\n")
	b.WriteString("# TYPE dock_radar_rolling_containers_failed_total counter\n")
	b.WriteString(fmt.Sprintf("dock_radar_rolling_containers_failed_total %d\n\n", stats.TotalContainersFailed))

	b.WriteString("# HELP dock_radar_rolling_rollbacks_total Total automatic rollbacks triggered due to readiness probe failures.\n")
	b.WriteString("# TYPE dock_radar_rolling_rollbacks_total counter\n")
	b.WriteString(fmt.Sprintf("dock_radar_rolling_rollbacks_total %d\n\n", stats.TotalRollbacks))
}
