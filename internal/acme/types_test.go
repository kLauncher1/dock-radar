package acme

import (
	"testing"
	"time"
)

func TestDefaultACMEConfig(t *testing.T) {
	cfg := DefaultACMEConfig()
	if !cfg.Enabled {
		t.Fatalf("expected Enabled=true, got %v", cfg.Enabled)
	}
	if cfg.Provider != ProviderLetsEncryptStaging {
		t.Fatalf("expected provider %s, got %s", ProviderLetsEncryptStaging, cfg.Provider)
	}
	if cfg.RenewThresholdDays != 30 {
		t.Fatalf("expected RenewThresholdDays=30, got %d", cfg.RenewThresholdDays)
	}
	if err := ValidateACMEConfig(cfg); err != nil {
		t.Fatalf("DefaultACMEConfig failed validation: %v", err)
	}
}

func TestValidateDomain(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.domain.org",
		"*.wildcard.dev",
		"localhost",
		"127.0.0.1",
		"::1",
		"192.168.1.50",
		"monitor.internal.infra.net",
	}
	for _, v := range valid {
		if err := ValidateDomain(v); err != nil {
			t.Errorf("expected %q to be valid, got: %v", v, err)
		}
	}

	invalid := []string{
		"",
		"   ",
		"http://example.com",
		"example..com",
		"-badprefix.com",
		"inv@lid.com",
		"space in domain.com",
	}
	for _, inv := range invalid {
		if err := ValidateDomain(inv); err == nil {
			t.Errorf("expected %q to be rejected, but passed validation", inv)
		}
	}
}

func TestValidateACMEConfig_Bounds(t *testing.T) {
	cfg := DefaultACMEConfig()

	// Invalid renew days
	cfg.RenewThresholdDays = 0
	if err := ValidateACMEConfig(cfg); err == nil {
		t.Errorf("expected error for RenewThresholdDays=0")
	}
	cfg.RenewThresholdDays = 91
	if err := ValidateACMEConfig(cfg); err == nil {
		t.Errorf("expected error for RenewThresholdDays=91")
	}
	cfg.RenewThresholdDays = 30

	// Invalid interval
	cfg.CheckInterval = 10 * time.Second
	if err := ValidateACMEConfig(cfg); err == nil {
		t.Errorf("expected error for CheckInterval < 1m")
	}
	cfg.CheckInterval = 1 * time.Hour

	// Invalid challenge type
	cfg.ChallengeType = "tls-alpn-01"
	if err := ValidateACMEConfig(cfg); err == nil {
		t.Errorf("expected error for unsupported challenge type")
	}
	cfg.ChallengeType = ChallengeDNS01

	// Custom provider with empty URL
	cfg.Provider = ProviderCustom
	cfg.DirectoryURL = ""
	if err := ValidateACMEConfig(cfg); err == nil {
		t.Errorf("expected error for custom provider with empty URL")
	}
}

func TestResolveDirectoryURL(t *testing.T) {
	if got := ResolveDirectoryURL(ProviderLetsEncrypt, ""); got != LetsEncryptDirectoryURL {
		t.Errorf("expected %s, got %s", LetsEncryptDirectoryURL, got)
	}
	if got := ResolveDirectoryURL(ProviderLetsEncryptStaging, ""); got != LetsEncryptStagingDirectoryURL {
		t.Errorf("expected %s, got %s", LetsEncryptStagingDirectoryURL, got)
	}
	if got := ResolveDirectoryURL(ProviderZeroSSL, ""); got != ZeroSSLDirectoryURL {
		t.Errorf("expected %s, got %s", ZeroSSLDirectoryURL, got)
	}
	custom := "https://pebble:14000/dir"
	if got := ResolveDirectoryURL(ProviderCustom, custom); got != custom {
		t.Errorf("expected %s, got %s", custom, got)
	}
}
