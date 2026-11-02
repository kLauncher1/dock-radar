package vault

import (
	"testing"
	"time"
)

func TestDefaultVaultConfig(t *testing.T) {
	cfg := DefaultVaultConfig()
	if !cfg.Enabled {
		t.Fatalf("expected vault to be enabled by default")
	}
	if !cfg.HardwareRootEnabled {
		t.Fatalf("expected hardware root to be enabled by default")
	}
	if cfg.MaxSecrets != 1000 {
		t.Fatalf("expected default max secrets 1000, got %d", cfg.MaxSecrets)
	}
	if err := ValidateVaultConfig(cfg); err != nil {
		t.Fatalf("expected default config to pass validation, got: %v", err)
	}
}

func TestValidateSecretKey(t *testing.T) {
	validKeys := []string{
		"DATABASE_URL",
		"docker/registry/token",
		"auth-service.jwt-secret",
		"api_key_123",
		"app/production/DB_PASS",
	}
	for _, key := range validKeys {
		if err := ValidateSecretKey(key); err != nil {
			t.Errorf("expected key '%s' to be valid, got: %v", key, err)
		}
	}

	invalidKeys := []string{
		"",
		"   ",
		"invalid key with spaces",
		"key_with_null\x00_byte",
		"key;with;semicolons",
		"key<with>brackets",
		"key$with$dollar",
		string(make([]byte, 129)), // length > 128
	}
	for _, key := range invalidKeys {
		if err := ValidateSecretKey(key); err == nil {
			t.Errorf("expected key '%s' to be invalid, but passed", key)
		}
	}
}

func TestValidateIDs(t *testing.T) {
	if err := ValidateSecretID("sec_a1b2c3d4e5f6"); err != nil {
		t.Errorf("expected valid secret ID, got: %v", err)
	}
	if err := ValidateSecretID("invalid_id"); err == nil {
		t.Errorf("expected error for invalid secret ID, passed")
	}

	if err := ValidateTokenID("tok_1234567890ab"); err != nil {
		t.Errorf("expected valid token ID, got: %v", err)
	}
	if err := ValidateTokenID("token_bad"); err == nil {
		t.Errorf("expected error for invalid token ID, passed")
	}

	if err := ValidateLeaseID("lse_deadbeef1234"); err != nil {
		t.Errorf("expected valid lease ID, got: %v", err)
	}
	if err := ValidateLeaseID("lease-invalid"); err == nil {
		t.Errorf("expected error for invalid lease ID, passed")
	}
}

func TestValidateVaultConfig_Bounds(t *testing.T) {
	cfg := DefaultVaultConfig()

	cfg.RotationInterval = 10 * time.Second
	if err := ValidateVaultConfig(cfg); err == nil {
		t.Errorf("expected error for rotation interval < 1m")
	}

	cfg = DefaultVaultConfig()
	cfg.DefaultLeaseTTL = 5 * time.Second
	if err := ValidateVaultConfig(cfg); err == nil {
		t.Errorf("expected error for default lease TTL < 10s")
	}

	cfg = DefaultVaultConfig()
	cfg.DefaultLeaseTTL = 10 * time.Hour
	cfg.MaxLeaseTTL = 2 * time.Hour
	if err := ValidateVaultConfig(cfg); err == nil {
		t.Errorf("expected error when default lease TTL > max lease TTL")
	}

	cfg = DefaultVaultConfig()
	cfg.MaxSecrets = 5
	if err := ValidateVaultConfig(cfg); err == nil {
		t.Errorf("expected error when max secrets < 10")
	}
}
