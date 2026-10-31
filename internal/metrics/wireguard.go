package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/wireguard"
)

// AppendWireGuardMetrics formats WireGuard mesh overlay telemetry into standard Prometheus exposition format.
func AppendWireGuardMetrics(builder *strings.Builder, status *wireguard.WireGuardStatus) {
	if status == nil {
		return
	}

	ifaceLabel := escapeLabel(status.InterfaceName)

	builder.WriteString("# HELP dock_radar_wireguard_enabled Whether the WireGuard mesh tunneling engine is enabled (1 or 0)\n")
	builder.WriteString("# TYPE dock_radar_wireguard_enabled gauge\n")
	enabledVal := 0
	if status.Enabled {
		enabledVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_wireguard_enabled{interface=\"%s\"} %d\n", ifaceLabel, enabledVal)

	builder.WriteString("# HELP dock_radar_wireguard_listen_port UDP port on which the WireGuard gateway listens\n")
	builder.WriteString("# TYPE dock_radar_wireguard_listen_port gauge\n")
	fmt.Fprintf(builder, "dock_radar_wireguard_listen_port{interface=\"%s\"} %d\n", ifaceLabel, status.ListenPort)

	builder.WriteString("# HELP dock_radar_wireguard_peers_count Total number of configured WireGuard peers\n")
	builder.WriteString("# TYPE dock_radar_wireguard_peers_count gauge\n")
	fmt.Fprintf(builder, "dock_radar_wireguard_peers_count{interface=\"%s\"} %d\n", ifaceLabel, status.TotalPeers)

	builder.WriteString("# HELP dock_radar_wireguard_peers_connected Number of actively connected WireGuard peers\n")
	builder.WriteString("# TYPE dock_radar_wireguard_peers_connected gauge\n")
	fmt.Fprintf(builder, "dock_radar_wireguard_peers_connected{interface=\"%s\"} %d\n", ifaceLabel, status.ActivePeers)

	builder.WriteString("# HELP dock_radar_wireguard_rx_bytes_total Cumulative encrypted bytes received over WireGuard tunnels\n")
	builder.WriteString("# TYPE dock_radar_wireguard_rx_bytes_total counter\n")
	fmt.Fprintf(builder, "dock_radar_wireguard_rx_bytes_total{interface=\"%s\"} %d\n", ifaceLabel, status.TotalRxBytes)

	builder.WriteString("# HELP dock_radar_wireguard_tx_bytes_total Cumulative encrypted bytes transmitted over WireGuard tunnels\n")
	builder.WriteString("# TYPE dock_radar_wireguard_tx_bytes_total counter\n")
	fmt.Fprintf(builder, "dock_radar_wireguard_tx_bytes_total{interface=\"%s\"} %d\n", ifaceLabel, status.TotalTxBytes)

	builder.WriteString("# HELP dock_radar_wireguard_active_leases Number of active overlay IP leases in the subnet\n")
	builder.WriteString("# TYPE dock_radar_wireguard_active_leases gauge\n")
	fmt.Fprintf(builder, "dock_radar_wireguard_active_leases{interface=\"%s\"} %d\n", ifaceLabel, status.ActiveLeases)

	builder.WriteString("# HELP dock_radar_wireguard_routing_rules_count Total active prefix routes in the cryptokey router\n")
	builder.WriteString("# TYPE dock_radar_wireguard_routing_rules_count gauge\n")
	fmt.Fprintf(builder, "dock_radar_wireguard_routing_rules_count{interface=\"%s\"} %d\n\n", ifaceLabel, status.RoutingRulesCount)
}
