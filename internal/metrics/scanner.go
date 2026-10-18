package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/scanner"
)

// AppendScannerMetrics formats container image vulnerability and SBOM telemetry into Prometheus exposition format.
func AppendScannerMetrics(builder *strings.Builder, status *scanner.ScannerStatus) {
	if status == nil {
		return
	}

	builder.WriteString("# HELP dock_radar_scanner_enabled Container vulnerability scanner status (1 if active, 0 otherwise)\n")
	builder.WriteString("# TYPE dock_radar_scanner_enabled gauge\n")
	enabledVal := 0
	if status.Enabled {
		enabledVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_scanner_enabled %d\n", enabledVal)

	builder.WriteString("# HELP dock_radar_scanner_images_scanned_total Total container images inspected for vulnerabilities\n")
	builder.WriteString("# TYPE dock_radar_scanner_images_scanned_total gauge\n")
	fmt.Fprintf(builder, "dock_radar_scanner_images_scanned_total %d\n", status.TotalScannedImages)

	builder.WriteString("# HELP dock_radar_scanner_vulnerabilities_total Identified CVE count segmented by CVSS severity\n")
	builder.WriteString("# TYPE dock_radar_scanner_vulnerabilities_total gauge\n")
	fmt.Fprintf(builder, "dock_radar_scanner_vulnerabilities_total{severity=\"critical\"} %d\n", status.CriticalCount)
	fmt.Fprintf(builder, "dock_radar_scanner_vulnerabilities_total{severity=\"high\"} %d\n", status.HighCount)
	fmt.Fprintf(builder, "dock_radar_scanner_vulnerabilities_total{severity=\"medium\"} %d\n", status.MediumCount)
	fmt.Fprintf(builder, "dock_radar_scanner_vulnerabilities_total{severity=\"low\"} %d\n", status.LowCount)

	builder.WriteString("# HELP dock_radar_scanner_risk_score Average security risk score across container workloads (0 to 100)\n")
	builder.WriteString("# TYPE dock_radar_scanner_risk_score gauge\n")
	fmt.Fprintf(builder, "dock_radar_scanner_risk_score %.1f\n", status.AverageRiskScore)

	builder.WriteString("# HELP dock_radar_scanner_gating_passed_total Total deployments passing security gating compliance\n")
	builder.WriteString("# TYPE dock_radar_scanner_gating_passed_total counter\n")
	fmt.Fprintf(builder, "dock_radar_scanner_gating_passed_total %d\n", status.GatingPassedCount)

	builder.WriteString("# HELP dock_radar_scanner_gating_blocked_total Total deployments blocked by security gating policy\n")
	builder.WriteString("# TYPE dock_radar_scanner_gating_blocked_total counter\n")
	fmt.Fprintf(builder, "dock_radar_scanner_gating_blocked_total %d\n", status.GatingBlockedCount)
}
