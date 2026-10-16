package metrics

import (
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/ebpf"
)

func TestAppendEBPFMetrics(t *testing.T) {
	status := ebpf.EBPFStatus{
		Enabled:             true,
		Mode:                ebpf.ProbeModeProcfs,
		ActiveFlows:         42,
		TotalFlowsTracked:   128,
		BytesIngressTotal:   500000,
		BytesEgressTotal:    250000,
		TotalSecurityAlerts: 3,
		TotalSyscallsTraced: 1024,
		CPUOverheadPercent:  0.08,
	}

	var sb strings.Builder
	AppendEBPFMetrics(&sb, status)

	out := sb.String()

	expectedSubstrings := []string{
		"dock_radar_ebpf_flows_active 42",
		"dock_radar_ebpf_flows_total 128",
		"dock_radar_ebpf_bytes_ingress_total 500000",
		"dock_radar_ebpf_bytes_egress_total 250000",
		"dock_radar_ebpf_security_alerts_total 3",
		"dock_radar_ebpf_syscalls_traced_total 1024",
		"dock_radar_ebpf_cpu_overhead_percent 0.0800",
		`dock_radar_ebpf_probe_active{mode="procfs_socket"} 1`,
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(out, sub) {
			t.Errorf("Expected output to contain %q, but got:\n%s", sub, out)
		}
	}
}
