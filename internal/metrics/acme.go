package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/acme"
)

// AppendACMEMetrics formats Automated TLS ACME & Dynamic SNI telemetry into Prometheus exposition format.
func AppendACMEMetrics(builder *strings.Builder, status *acme.ACMEStatus) {
	if status == nil {
		return
	}

	builder.WriteString("# HELP dock_radar_acme_enabled Whether automated ACME certbot and dynamic SNI engine is active (1 or 0)\n")
	builder.WriteString("# TYPE dock_radar_acme_enabled gauge\n")
	enabledVal := 0
	if status.Enabled {
		enabledVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_acme_enabled %d\n", enabledVal)

	builder.WriteString("# HELP dock_radar_acme_certificates_total Total number of managed TLS certificates\n")
	builder.WriteString("# TYPE dock_radar_acme_certificates_total gauge\n")
	fmt.Fprintf(builder, "dock_radar_acme_certificates_total %d\n", status.TotalCertificates)

	builder.WriteString("# HELP dock_radar_acme_certificates_valid Number of currently valid TLS certificates\n")
	builder.WriteString("# TYPE dock_radar_acme_certificates_valid gauge\n")
	fmt.Fprintf(builder, "dock_radar_acme_certificates_valid %d\n", status.ValidCertificates)

	builder.WriteString("# HELP dock_radar_acme_certificates_expiring_soon Certificates approaching expiration threshold\n")
	builder.WriteString("# TYPE dock_radar_acme_certificates_expiring_soon gauge\n")
	fmt.Fprintf(builder, "dock_radar_acme_certificates_expiring_soon %d\n", status.ExpiringSoonCount)

	builder.WriteString("# HELP dock_radar_acme_certificates_expired Expired TLS certificates awaiting renewal\n")
	builder.WriteString("# TYPE dock_radar_acme_certificates_expired gauge\n")
	fmt.Fprintf(builder, "dock_radar_acme_certificates_expired %d\n", status.ExpiredCount)

	builder.WriteString("# HELP dock_radar_acme_renewals_total Cumulative count of certificate renewals executed\n")
	builder.WriteString("# TYPE dock_radar_acme_renewals_total counter\n")
	fmt.Fprintf(builder, "dock_radar_acme_renewals_total %d\n", status.TotalRenewals)

	builder.WriteString("# HELP dock_radar_acme_renewals_failed_total Cumulative count of failed certificate renewals\n")
	builder.WriteString("# TYPE dock_radar_acme_renewals_failed_total counter\n")
	fmt.Fprintf(builder, "dock_radar_acme_renewals_failed_total %d\n", status.FailedRenewals)

	builder.WriteString("# HELP dock_radar_acme_active_challenges Current in-flight HTTP-01 and DNS-01 verification challenges\n")
	builder.WriteString("# TYPE dock_radar_acme_active_challenges gauge\n")
	fmt.Fprintf(builder, "dock_radar_acme_active_challenges %d\n", status.ActiveChallenges)

	builder.WriteString("# HELP dock_radar_acme_sni_routes_count Active domain and SAN routes multiplexed via Dynamic SNI\n")
	builder.WriteString("# TYPE dock_radar_acme_sni_routes_count gauge\n")
	fmt.Fprintf(builder, "dock_radar_acme_sni_routes_count %d\n", status.SNIRoutesCount)

	builder.WriteString("# HELP dock_radar_acme_renew_threshold_days Days-until-expiration threshold triggering automatic renewal\n")
	builder.WriteString("# TYPE dock_radar_acme_renew_threshold_days gauge\n")
	fmt.Fprintf(builder, "dock_radar_acme_renew_threshold_days %d\n\n", status.RenewThresholdDays)
}
