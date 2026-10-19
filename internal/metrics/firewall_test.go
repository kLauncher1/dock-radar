package metrics

import (
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/firewall"
)

func TestAppendFirewallMetrics(t *testing.T) {
	var builder strings.Builder

	status := &firewall.FirewallStatus{
		Enabled:               true,
		ZeroTrustActive:       true,
		TotalRules:            12,
		ActiveRules:           10,
		IsolatedContainers:    3,
		QuarantinedContainers: 1,
		TotalPacketsEvaluated: 15000,
		TotalPacketsAllowed:   14000,
		TotalPacketsBlocked:   800,
		TotalPacketsThrottled: 200,
		TotalBytesEvaluated:   5000000,
		TotalBytesBlocked:     250000,
		ActiveDDoSAlerts:      2,
	}

	AppendFirewallMetrics(&builder, status)
	out := builder.String()

	expectedSubstrings := []string{
		"dock_radar_firewall_enabled 1",
		"dock_radar_firewall_zerotrust_active 1",
		"dock_radar_firewall_rules_total 12",
		"dock_radar_firewall_rules_active 10",
		"dock_radar_firewall_isolated_containers 3",
		"dock_radar_firewall_quarantined_containers 1",
		"dock_radar_firewall_packets_evaluated_total 15000",
		"dock_radar_firewall_packets_allowed_total 14000",
		"dock_radar_firewall_packets_blocked_total 800",
		"dock_radar_firewall_packets_throttled_total 200",
		"dock_radar_firewall_bytes_evaluated_total 5000000",
		"dock_radar_firewall_bytes_blocked_total 250000",
		"dock_radar_firewall_ddos_alerts_active 2",
	}

	for _, s := range expectedSubstrings {
		if !strings.Contains(out, s) {
			t.Errorf("missing expected prometheus metric: %s\nGot:\n%s", s, out)
		}
	}

	// Test nil guard
	var nilBuilder strings.Builder
	AppendFirewallMetrics(&nilBuilder, nil)
	if nilBuilder.Len() != 0 {
		t.Fatalf("expected empty output for nil status")
	}
}
