package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/ebpf"
)

// AppendEBPFMetrics formats eBPF and socket telemetry into Prometheus exposition format.
func AppendEBPFMetrics(builder *strings.Builder, status ebpf.EBPFStatus) {
	builder.WriteString("# HELP dock_radar_ebpf_flows_active Current active socket connection flows tracked\n")
	builder.WriteString("# TYPE dock_radar_ebpf_flows_active gauge\n")
	fmt.Fprintf(builder, "dock_radar_ebpf_flows_active %d\n", status.ActiveFlows)

	builder.WriteString("# HELP dock_radar_ebpf_flows_total Total connection flows tracked since inception\n")
	builder.WriteString("# TYPE dock_radar_ebpf_flows_total counter\n")
	fmt.Fprintf(builder, "dock_radar_ebpf_flows_total %d\n", status.TotalFlowsTracked)

	builder.WriteString("# HELP dock_radar_ebpf_bytes_ingress_total Total ingress socket bytes tracked\n")
	builder.WriteString("# TYPE dock_radar_ebpf_bytes_ingress_total counter\n")
	fmt.Fprintf(builder, "dock_radar_ebpf_bytes_ingress_total %d\n", status.BytesIngressTotal)

	builder.WriteString("# HELP dock_radar_ebpf_bytes_egress_total Total egress socket bytes tracked\n")
	builder.WriteString("# TYPE dock_radar_ebpf_bytes_egress_total counter\n")
	fmt.Fprintf(builder, "dock_radar_ebpf_bytes_egress_total %d\n", status.BytesEgressTotal)

	builder.WriteString("# HELP dock_radar_ebpf_security_alerts_total Cumulative kernel security alerts detected\n")
	builder.WriteString("# TYPE dock_radar_ebpf_security_alerts_total counter\n")
	fmt.Fprintf(builder, "dock_radar_ebpf_security_alerts_total %d\n", status.TotalSecurityAlerts)

	builder.WriteString("# HELP dock_radar_ebpf_syscalls_traced_total Low-level system calls traced\n")
	builder.WriteString("# TYPE dock_radar_ebpf_syscalls_traced_total counter\n")
	fmt.Fprintf(builder, "dock_radar_ebpf_syscalls_traced_total %d\n", status.TotalSyscallsTraced)

	builder.WriteString("# HELP dock_radar_ebpf_cpu_overhead_percent Estimated probe CPU overhead percentage\n")
	builder.WriteString("# TYPE dock_radar_ebpf_cpu_overhead_percent gauge\n")
	fmt.Fprintf(builder, "dock_radar_ebpf_cpu_overhead_percent %.4f\n", status.CPUOverheadPercent)

	builder.WriteString("# HELP dock_radar_ebpf_probe_active Probe status (1 if enabled, 0 otherwise)\n")
	builder.WriteString("# TYPE dock_radar_ebpf_probe_active gauge\n")
	activeVal := 0
	if status.Enabled {
		activeVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_ebpf_probe_active{mode=\"%s\"} %d\n", status.Mode, activeVal)
}
