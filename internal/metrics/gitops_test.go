package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/gitops"
)

func TestAppendGitOpsMetrics(t *testing.T) {
	var b strings.Builder
	AppendGitOpsMetrics(&b, nil)
	if b.Len() != 0 {
		t.Errorf("expected empty string for nil status")
	}

	status := &gitops.GitOpsStatus{
		Enabled:                true,
		TrackedReposCount:      3,
		TotalDeployments:       10,
		SuccessfulDeployments:  8,
		RolledBackDeployments:  1,
		FailedDeployments:      1,
		SignatureFailuresTotal: 2,
		LastSyncTime:           time.Unix(1700000000, 0),
	}

	AppendGitOpsMetrics(&b, status)
	res := b.String()

	expectedSubstrings := []string{
		"dock_radar_gitops_enabled 1",
		"dock_radar_gitops_tracked_repos 3",
		"dock_radar_gitops_deployments_total 10",
		"dock_radar_gitops_deployments_success_total 8",
		"dock_radar_gitops_deployments_rollback_total 1",
		"dock_radar_gitops_signature_failures_total 2",
		"dock_radar_gitops_last_sync_timestamp_seconds 1700000000",
	}

	for _, substr := range expectedSubstrings {
		if !strings.Contains(res, substr) {
			t.Errorf("missing expected substring %q in formatted output", substr)
		}
	}
}
