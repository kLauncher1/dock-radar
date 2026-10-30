package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/gitops"
)

// AppendGitOpsMetrics formats GitOps continuous sync, rollout, and rollback telemetry into standard Prometheus exposition format.
func AppendGitOpsMetrics(builder *strings.Builder, status *gitops.GitOpsStatus) {
	if status == nil {
		return
	}

	builder.WriteString("# HELP dock_radar_gitops_enabled GitOps continuous sync engine status (1 if active, 0 otherwise)\n")
	builder.WriteString("# TYPE dock_radar_gitops_enabled gauge\n")
	enabledVal := 0
	if status.Enabled {
		enabledVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_gitops_enabled %d\n", enabledVal)

	builder.WriteString("# HELP dock_radar_gitops_tracked_repos Number of continuously tracked Git repositories\n")
	builder.WriteString("# TYPE dock_radar_gitops_tracked_repos gauge\n")
	fmt.Fprintf(builder, "dock_radar_gitops_tracked_repos %d\n", status.TrackedReposCount)

	builder.WriteString("# HELP dock_radar_gitops_deployments_total Cumulative GitOps rollout attempts\n")
	builder.WriteString("# TYPE dock_radar_gitops_deployments_total counter\n")
	fmt.Fprintf(builder, "dock_radar_gitops_deployments_total %d\n", status.TotalDeployments)

	builder.WriteString("# HELP dock_radar_gitops_deployments_success_total Cumulative successful GitOps rollouts\n")
	builder.WriteString("# TYPE dock_radar_gitops_deployments_success_total counter\n")
	fmt.Fprintf(builder, "dock_radar_gitops_deployments_success_total %d\n", status.SuccessfulDeployments)

	builder.WriteString("# HELP dock_radar_gitops_deployments_rollback_total Cumulative automated or manual rollbacks triggered\n")
	builder.WriteString("# TYPE dock_radar_gitops_deployments_rollback_total counter\n")
	fmt.Fprintf(builder, "dock_radar_gitops_deployments_rollback_total %d\n", status.RolledBackDeployments)

	builder.WriteString("# HELP dock_radar_gitops_deployments_failed_total Cumulative failed GitOps rollouts\n")
	builder.WriteString("# TYPE dock_radar_gitops_deployments_failed_total counter\n")
	fmt.Fprintf(builder, "dock_radar_gitops_deployments_failed_total %d\n", status.FailedDeployments)

	builder.WriteString("# HELP dock_radar_gitops_signature_failures_total Cumulative commit or webhook cryptographic signature validation rejections\n")
	builder.WriteString("# TYPE dock_radar_gitops_signature_failures_total counter\n")
	fmt.Fprintf(builder, "dock_radar_gitops_signature_failures_total %d\n", status.SignatureFailuresTotal)

	if !status.LastSyncTime.IsZero() {
		builder.WriteString("# HELP dock_radar_gitops_last_sync_timestamp_seconds Unix timestamp of last repository synchronization\n")
		builder.WriteString("# TYPE dock_radar_gitops_last_sync_timestamp_seconds gauge\n")
		fmt.Fprintf(builder, "dock_radar_gitops_last_sync_timestamp_seconds %d\n", status.LastSyncTime.Unix())
	}
}
