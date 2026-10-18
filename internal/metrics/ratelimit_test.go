package metrics

import (
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/ratelimit"
)

func TestAppendRateLimitMetrics(t *testing.T) {
	status := &ratelimit.LimiterStatus{
		Enabled:                 true,
		TotalTenants:            5,
		ActiveBannedIPs:         2,
		TotalEvaluations:        1500,
		TotalThrottledRequests:  42,
		TotalBannedRejections:   18,
		TotalBandwidthThrottled: 7,
		SyncedPeersCount:        3,
	}

	var builder strings.Builder
	AppendRateLimitMetrics(&builder, status)
	output := builder.String()

	expectedSubstrings := []string{
		"dock_radar_ratelimit_enabled 1",
		"dock_radar_ratelimit_tenants_total 5",
		"dock_radar_ratelimit_banned_ips_active 2",
		"dock_radar_ratelimit_evaluations_total 1500",
		"dock_radar_ratelimit_throttled_total 42",
		"dock_radar_ratelimit_banned_rejections_total 18",
		"dock_radar_ratelimit_bandwidth_throttled_total 7",
		"dock_radar_ratelimit_synced_peers_count 3",
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(output, sub) {
			t.Fatalf("expected output to contain %q, but got:\n%s", sub, output)
		}
	}
}

func TestAppendRateLimitMetrics_NilGuard(t *testing.T) {
	var builder strings.Builder
	AppendRateLimitMetrics(&builder, nil)
	if builder.Len() != 0 {
		t.Fatalf("expected empty output for nil status, got: %s", builder.String())
	}
}
