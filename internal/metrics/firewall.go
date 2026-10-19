package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/firewall"
)

// AppendFirewallMetrics formats eBPF micro-firewall and network isolation telemetry into Prometheus exposition format.
func AppendFirewallMetrics(builder *strings.Builder, status *firewall.FirewallStatus) {
	if status == nil {
		return
	}

	builder.WriteString("# HELP dock_radar_firewall_enabled Micro-firewall engine status (1 if active, 0 otherwise)\n")
	builder.WriteString("# TYPE dock_radar_firewall_enabled gauge\n")
	enabledVal := 0
	if status.Enabled {
		enabledVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_firewall_enabled %d\n", enabledVal)

	builder.WriteString("# HELP dock_radar_firewall_zerotrust_active Zero-trust network policy status (1 if active, 0 otherwise)\n")
	builder.WriteString("# TYPE dock_radar_firewall_zerotrust_active gauge\n")
	ztVal := 0
	if status.ZeroTrustActive {
		ztVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_firewall_zerotrust_active %d\n", ztVal)

	builder.WriteString("# HELP dock_radar_firewall_rules_total Total configured firewall filtering rules\n")
	builder.WriteString("# TYPE dock_radar_firewall_rules_total gauge\n")
	fmt.Fprintf(builder, "dock_radar_firewall_rules_total %d\n", status.TotalRules)

	builder.WriteString("# HELP dock_radar_firewall_rules_active Number of active enabled firewall rules\n")
	builder.WriteString("# TYPE dock_radar_firewall_rules_active gauge\n")
	fmt.Fprintf(builder, "dock_radar_firewall_rules_active %d\n", status.ActiveRules)

	builder.WriteString("# HELP dock_radar_firewall_isolated_containers Number of containers with active isolation policies\n")
	builder.WriteString("# TYPE dock_radar_firewall_isolated_containers gauge\n")
	fmt.Fprintf(builder, "dock_radar_firewall_isolated_containers %d\n", status.IsolatedContainers)

	builder.WriteString("# HELP dock_radar_firewall_quarantined_containers Number of containers in complete network quarantine\n")
	builder.WriteString("# TYPE dock_radar_firewall_quarantined_containers gauge\n")
	fmt.Fprintf(builder, "dock_radar_firewall_quarantined_containers %d\n", status.QuarantinedContainers)

	builder.WriteString("# HELP dock_radar_firewall_packets_evaluated_total Cumulative network packets evaluated\n")
	builder.WriteString("# TYPE dock_radar_firewall_packets_evaluated_total counter\n")
	fmt.Fprintf(builder, "dock_radar_firewall_packets_evaluated_total %d\n", status.TotalPacketsEvaluated)

	builder.WriteString("# HELP dock_radar_firewall_packets_allowed_total Cumulative network packets permitted\n")
	builder.WriteString("# TYPE dock_radar_firewall_packets_allowed_total counter\n")
	fmt.Fprintf(builder, "dock_radar_firewall_packets_allowed_total %d\n", status.TotalPacketsAllowed)

	builder.WriteString("# HELP dock_radar_firewall_packets_blocked_total Cumulative network packets dropped or rejected\n")
	builder.WriteString("# TYPE dock_radar_firewall_packets_blocked_total counter\n")
	fmt.Fprintf(builder, "dock_radar_firewall_packets_blocked_total %d\n", status.TotalPacketsBlocked)

	builder.WriteString("# HELP dock_radar_firewall_packets_throttled_total Cumulative network packets throttled due to DDoS flood\n")
	builder.WriteString("# TYPE dock_radar_firewall_packets_throttled_total counter\n")
	fmt.Fprintf(builder, "dock_radar_firewall_packets_throttled_total %d\n", status.TotalPacketsThrottled)

	builder.WriteString("# HELP dock_radar_firewall_bytes_evaluated_total Cumulative network traffic volume evaluated in bytes\n")
	builder.WriteString("# TYPE dock_radar_firewall_bytes_evaluated_total counter\n")
	fmt.Fprintf(builder, "dock_radar_firewall_bytes_evaluated_total %d\n", status.TotalBytesEvaluated)

	builder.WriteString("# HELP dock_radar_firewall_bytes_blocked_total Cumulative network traffic volume blocked in bytes\n")
	builder.WriteString("# TYPE dock_radar_firewall_bytes_blocked_total counter\n")
	fmt.Fprintf(builder, "dock_radar_firewall_bytes_blocked_total %d\n", status.TotalBytesBlocked)

	builder.WriteString("# HELP dock_radar_firewall_ddos_alerts_active Number of active DDoS alert events recorded\n")
	builder.WriteString("# TYPE dock_radar_firewall_ddos_alerts_active gauge\n")
	fmt.Fprintf(builder, "dock_radar_firewall_ddos_alerts_active %d\n", status.ActiveDDoSAlerts)
}
