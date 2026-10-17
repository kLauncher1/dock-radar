package metrics

import (
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/federation"
)

func TestAppendFederationMetrics(t *testing.T) {
	var sb strings.Builder

	// Test nil status
	AppendFederationMetrics(&sb, nil)
	if sb.Len() != 0 {
		t.Fatalf("expected 0 bytes for nil status, got %d", sb.Len())
	}

	status := &federation.FederationStatus{
		Enabled:         true,
		LocalRegionID:   "us-east-1",
		TotalRegions:    4,
		HealthyRegions:  3,
		ActiveTunnels:   3,
		TotalSyncBytes:  1048576,
		TotalSavedBytes: 4194304,
		FailoverCount:   2,
	}

	AppendFederationMetrics(&sb, status)
	out := sb.String()

	expectedGauges := []string{
		"dock_radar_federation_regions_total 4",
		"dock_radar_federation_regions_healthy 3",
		"dock_radar_federation_tunnels_active 3",
		"dock_radar_federation_wan_sync_bytes_total 1048576",
		"dock_radar_federation_wan_sync_saved_bytes_total 4194304",
		"dock_radar_federation_failover_events_total 2",
		"dock_radar_federation_enabled{local_region=\"us-east-1\"} 1",
	}

	for _, expected := range expectedGauges {
		if !strings.Contains(out, expected) {
			t.Errorf("missing expected metrics output line %q in:\n%s", expected, out)
		}
	}
}
