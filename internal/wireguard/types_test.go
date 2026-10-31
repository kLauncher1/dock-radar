package wireguard

import (
	"encoding/base64"
	"testing"
)

func TestDefaultWireGuardConfig(t *testing.T) {
	cfg := DefaultWireGuardConfig()
	if !cfg.Enabled {
		t.Errorf("expected default config to be enabled")
	}
	if cfg.ListenPort != 51820 {
		t.Errorf("expected listen port 51820, got %d", cfg.ListenPort)
	}
	if cfg.InterfaceName != "wg-radar0" {
		t.Errorf("expected interface name wg-radar0, got %s", cfg.InterfaceName)
	}
	if cfg.VirtualCIDR != "10.42.0.0/24" {
		t.Errorf("expected virtual CIDR 10.42.0.0/24, got %s", cfg.VirtualCIDR)
	}
}

func TestValidatePeerID(t *testing.T) {
	valid := []string{"peer-1", "node.alpha_99", "edge-us-east"}
	for _, id := range valid {
		if err := ValidatePeerID(id); err != nil {
			t.Errorf("expected peer ID %q to be valid, got %v", id, err)
		}
	}

	invalid := []string{"", "peer with spaces", "peer/slash", "peer$bad", string(make([]byte, 70))}
	for _, id := range invalid {
		if err := ValidatePeerID(id); err == nil {
			t.Errorf("expected peer ID %q to fail validation", id)
		}
	}
}

func TestValidateCIDR(t *testing.T) {
	ipNet, err := ValidateCIDR("10.42.0.0/24")
	if err != nil || ipNet == nil {
		t.Fatalf("expected valid CIDR, got err: %v", err)
	}

	if _, err := ValidateCIDR("invalid-cidr"); err == nil {
		t.Errorf("expected invalid CIDR error")
	}
}

func TestValidateKey(t *testing.T) {
	validKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := ValidateKey(validKey); err != nil {
		t.Errorf("expected valid 32-byte key, got %v", err)
	}

	shortKey := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if err := ValidateKey(shortKey); err == nil {
		t.Errorf("expected short key to fail validation")
	}

	if err := ValidateKey("not-base64!!!"); err == nil {
		t.Errorf("expected corrupt base64 to fail validation")
	}
}

func TestValidatePort(t *testing.T) {
	if err := ValidatePort(51820); err != nil {
		t.Errorf("expected port 51820 to be valid, got %v", err)
	}
	if err := ValidatePort(0); err == nil {
		t.Errorf("expected port 0 to fail")
	}
	if err := ValidatePort(70000); err == nil {
		t.Errorf("expected port 70000 to fail")
	}
}

func TestMaskKey(t *testing.T) {
	masked := MaskKey("abcdefghijklmnopqrstuvwxyz123456")
	if masked != "abcd....3456" {
		t.Errorf("expected abcd....3456, got %s", masked)
	}

	short := MaskKey("short")
	if short != "********" {
		t.Errorf("expected ********, got %s", short)
	}
}
