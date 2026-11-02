package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/vault"
)

// AppendVaultMetrics formats Zero-Knowledge Distributed Configuration Vault telemetry into Prometheus exposition format.
func AppendVaultMetrics(builder *strings.Builder, status *vault.VaultStatus) {
	if status == nil {
		return
	}

	builder.WriteString("# HELP dock_radar_vault_enabled Whether the zero-knowledge configuration vault is enabled (1 or 0)\n")
	builder.WriteString("# TYPE dock_radar_vault_enabled gauge\n")
	enabledVal := 0
	if status.Enabled {
		enabledVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_vault_enabled %d\n", enabledVal)

	builder.WriteString("# HELP dock_radar_vault_secrets_total Total number of encrypted configuration secrets stored in vault\n")
	builder.WriteString("# TYPE dock_radar_vault_secrets_total gauge\n")
	fmt.Fprintf(builder, "dock_radar_vault_secrets_total %d\n", status.TotalSecrets)

	builder.WriteString("# HELP dock_radar_vault_leases_active Number of currently active ephemeral secret access leases\n")
	builder.WriteString("# TYPE dock_radar_vault_leases_active gauge\n")
	fmt.Fprintf(builder, "dock_radar_vault_leases_active %d\n", status.ActiveLeases)

	builder.WriteString("# HELP dock_radar_vault_leases_shredded_total Cumulative number of expired or revoked leases shredded\n")
	builder.WriteString("# TYPE dock_radar_vault_leases_shredded_total counter\n")
	fmt.Fprintf(builder, "dock_radar_vault_leases_shredded_total %d\n", status.ShreddedLeases)

	builder.WriteString("# HELP dock_radar_vault_join_tokens_active Total cluster join tokens currently provisioned\n")
	builder.WriteString("# TYPE dock_radar_vault_join_tokens_active gauge\n")
	fmt.Fprintf(builder, "dock_radar_vault_join_tokens_active %d\n", status.JoinTokensCount)

	builder.WriteString("# HELP dock_radar_vault_replications_synced_total Cumulative configuration replication events ingested\n")
	builder.WriteString("# TYPE dock_radar_vault_replications_synced_total counter\n")
	fmt.Fprintf(builder, "dock_radar_vault_replications_synced_total %d\n", status.ReplicationsSynced)

	builder.WriteString("# HELP dock_radar_vault_hardware_root_active Whether hardware-rooted key derivation is actively protecting the vault\n")
	builder.WriteString("# TYPE dock_radar_vault_hardware_root_active gauge\n")
	hwActive := 0
	if status.HardwareRootActive {
		hwActive = 1
	}
	fmt.Fprintf(builder, "dock_radar_vault_hardware_root_active %d\n", hwActive)

	builder.WriteString("# HELP dock_radar_vault_key_age_seconds Age of the currently active master key in seconds\n")
	builder.WriteString("# TYPE dock_radar_vault_key_age_seconds gauge\n")
	fmt.Fprintf(builder, "dock_radar_vault_key_age_seconds %d\n", status.KeyAgeSeconds)

	builder.WriteString("# HELP dock_radar_vault_next_rotation_seconds Seconds remaining until scheduled automatic master key rotation\n")
	builder.WriteString("# TYPE dock_radar_vault_next_rotation_seconds gauge\n")
	fmt.Fprintf(builder, "dock_radar_vault_next_rotation_seconds %d\n\n", status.NextRotationSeconds)
}
