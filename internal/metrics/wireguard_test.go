package metrics

import (
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/wireguard"
)

func TestAppendWireGuardMetrics(t *testing.T) {
	st := &wireguard.WireGuardStatus{
		Enabled:           true,
		InterfaceName:     "wg-radar0",
		ListenPort:        51820,
		ActivePeers:       3,
		TotalPeers:        5,
		TotalRxBytes:      1048576,
		TotalTxBytes:      2097152,
		ActiveLeases:      4,
		RoutingRulesCount: 6,
	}

	var sb strings.Builder
	AppendWireGuardMetrics(&sb, st)

	out := sb.String()
	expectedMetrics := []string{
		"dock_radar_wireguard_enabled{interface=\"wg-radar0\"} 1",
		"dock_radar_wireguard_listen_port{interface=\"wg-radar0\"} 51820",
		"dock_radar_wireguard_peers_count{interface=\"wg-radar0\"} 5",
		"dock_radar_wireguard_peers_connected{interface=\"wg-radar0\"} 3",
		"dock_radar_wireguard_rx_bytes_total{interface=\"wg-radar0\"} 1048576",
		"dock_radar_wireguard_tx_bytes_total{interface=\"wg-radar0\"} 2097152",
		"dock_radar_wireguard_active_leases{interface=\"wg-radar0\"} 4",
		"dock_radar_wireguard_routing_rules_count{interface=\"wg-radar0\"} 6",
	}

	for _, m := range expectedMetrics {
		if !strings.Contains(out, m) {
			t.Errorf("missing expected metric line: %q", m)
		}
	}

	// Nil guard
	var sbNil strings.Builder
	AppendWireGuardMetrics(&sbNil, nil)
	if sbNil.Len() != 0 {
		t.Errorf("expected empty string on nil status")
	}
}
