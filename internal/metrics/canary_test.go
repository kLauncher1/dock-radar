package metrics

import (
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/canary"
)

func TestAppendCanaryMetrics(t *testing.T) {
	st := &canary.CanaryStatus{
		Enabled:           true,
		ActiveDeployments: 2,
		TotalDeployments:  3,
		TotalRoutedReqs:   15000,
		TotalMirroredReqs: 4500,
		TotalRollbacks:    1,
	}

	deps := []*canary.CanaryDeployment{
		{
			ID: "payments-api-v2",
			Traffic: canary.TrafficSplitConfig{
				BaselineWeight: 80,
				CanaryWeight:   20,
			},
		},
	}

	var sb strings.Builder
	AppendCanaryMetrics(&sb, st, deps)

	out := sb.String()
	expectedMetrics := []string{
		"dock_radar_canary_enabled 1",
		"dock_radar_canary_active_deployments 2",
		"dock_radar_canary_total_deployments 3",
		"dock_radar_canary_requests_routed_total 15000",
		"dock_radar_canary_requests_mirrored_total 4500",
		"dock_radar_canary_rollbacks_total 1",
		"dock_radar_canary_traffic_weight{deployment=\"payments-api-v2\",target=\"canary\"} 20",
		"dock_radar_canary_traffic_weight{deployment=\"payments-api-v2\",target=\"baseline\"} 80",
	}

	for _, m := range expectedMetrics {
		if !strings.Contains(out, m) {
			t.Errorf("missing expected metric line: %q", m)
		}
	}

	// Nil guard
	var sbNil strings.Builder
	AppendCanaryMetrics(&sbNil, nil, nil)
	if sbNil.Len() != 0 {
		t.Errorf("expected empty string on nil status")
	}
}
