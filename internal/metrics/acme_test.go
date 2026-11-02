package metrics

import (
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/acme"
)

func TestAppendACMEMetrics(t *testing.T) {
	status := &acme.ACMEStatus{
		Enabled:            true,
		TotalCertificates:  3,
		ValidCertificates:  2,
		ExpiringSoonCount:  1,
		ExpiredCount:       0,
		TotalRenewals:      14,
		FailedRenewals:     1,
		ActiveChallenges:   2,
		SNIRoutesCount:     7,
		RenewThresholdDays: 30,
	}

	var sb strings.Builder
	AppendACMEMetrics(&sb, status)
	out := sb.String()

	expectedMetrics := []string{
		"dock_radar_acme_enabled 1",
		"dock_radar_acme_certificates_total 3",
		"dock_radar_acme_certificates_valid 2",
		"dock_radar_acme_certificates_expiring_soon 1",
		"dock_radar_acme_certificates_expired 0",
		"dock_radar_acme_renewals_total 14",
		"dock_radar_acme_renewals_failed_total 1",
		"dock_radar_acme_active_challenges 2",
		"dock_radar_acme_sni_routes_count 7",
		"dock_radar_acme_renew_threshold_days 30",
	}

	for _, m := range expectedMetrics {
		if !strings.Contains(out, m) {
			t.Errorf("expected output to contain %q, but got:\n%s", m, out)
		}
	}
}

func TestAppendACMEMetrics_NilStatus(t *testing.T) {
	var sb strings.Builder
	AppendACMEMetrics(&sb, nil)
	if sb.Len() != 0 {
		t.Errorf("expected empty string for nil status")
	}
}
