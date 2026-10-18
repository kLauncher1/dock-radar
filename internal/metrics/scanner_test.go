package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/scanner"
)

func TestAppendScannerMetrics_AllGauges(t *testing.T) {
	status := &scanner.ScannerStatus{
		Enabled:              true,
		AutoScan:             true,
		TotalScannedImages:   5,
		TotalVulnerabilities: 12,
		CriticalCount:        2,
		HighCount:            4,
		MediumCount:          5,
		LowCount:             1,
		AverageRiskScore:     45.5,
		GatingPassedCount:    3,
		GatingBlockedCount:   2,
		LastScanAt:           time.Now().UTC(),
	}

	var b strings.Builder
	AppendScannerMetrics(&b, status)
	out := b.String()

	expectedSubstrings := []string{
		"dock_radar_scanner_enabled 1",
		"dock_radar_scanner_images_scanned_total 5",
		`dock_radar_scanner_vulnerabilities_total{severity="critical"} 2`,
		`dock_radar_scanner_vulnerabilities_total{severity="high"} 4`,
		"dock_radar_scanner_risk_score 45.5",
		"dock_radar_scanner_gating_passed_total 3",
		"dock_radar_scanner_gating_blocked_total 2",
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(out, sub) {
			t.Errorf("expected output to contain %q, but got:\n%s", sub, out)
		}
	}
}

func TestAppendScannerMetrics_NilStatus(t *testing.T) {
	var b strings.Builder
	AppendScannerMetrics(&b, nil)
	if b.Len() != 0 {
		t.Errorf("expected empty string for nil status, got %q", b.String())
	}
}
