package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/vault"
)

func TestAppendVaultMetrics(t *testing.T) {
	status := &vault.VaultStatus{
		Enabled:             true,
		TotalSecrets:        42,
		ActiveLeases:        5,
		ShreddedLeases:      18,
		ActiveKeyID:         "key_12345678",
		KeyAgeSeconds:       3600,
		NextRotationSeconds: 82800,
		JoinTokensCount:     3,
		ReplicationsSynced:  12,
		HardwareRootActive:  true,
		LastRotation:        time.Now().UTC(),
	}

	var b strings.Builder
	AppendVaultMetrics(&b, status)
	out := b.String()

	expectedMetrics := []string{
		"dock_radar_vault_enabled 1",
		"dock_radar_vault_secrets_total 42",
		"dock_radar_vault_leases_active 5",
		"dock_radar_vault_leases_shredded_total 18",
		"dock_radar_vault_join_tokens_active 3",
		"dock_radar_vault_replications_synced_total 12",
		"dock_radar_vault_hardware_root_active 1",
		"dock_radar_vault_key_age_seconds 3600",
		"dock_radar_vault_next_rotation_seconds 82800",
	}

	for _, m := range expectedMetrics {
		if !strings.Contains(out, m) {
			t.Errorf("expected metric '%s' in output, got:\n%s", m, out)
		}
	}

	// Test nil status
	var empty strings.Builder
	AppendVaultMetrics(&empty, nil)
	if empty.Len() != 0 {
		t.Errorf("expected nil status to append nothing, got %d bytes", empty.Len())
	}
}
