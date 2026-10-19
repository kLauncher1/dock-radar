package firewall

import (
	"testing"
)

func TestDefaultFirewallConfig(t *testing.T) {
	cfg := DefaultFirewallConfig()
	if !cfg.Enabled {
		t.Fatalf("expected Enabled=true")
	}
	if cfg.DefaultAction != ActionAllow {
		t.Fatalf("expected ActionAllow, got %s", cfg.DefaultAction)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config validation failed: %v", err)
	}
}

func TestFirewallConfig_Validate(t *testing.T) {
	cfg := DefaultFirewallConfig()
	cfg.MaxRules = 2
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for max_rules < 10")
	}

	cfg = DefaultFirewallConfig()
	cfg.DDoSThresholdPPS = 10
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for ddos_threshold_pps < 100")
	}

	cfg = DefaultFirewallConfig()
	cfg.DDoSCooldownSec = 2
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for ddos_cooldown_sec < 5")
	}
}

func TestFirewallRule_Validate(t *testing.T) {
	r := FirewallRule{
		ID:          "fw-rule-01",
		Name:        "Block Internal Telnet",
		Priority:    10,
		Enabled:     true,
		Direction:   DirectionIngress,
		Action:      ActionDrop,
		Protocol:    ProtocolTCP,
		SourceCIDR:  "172.17.0.0/16",
		SourcePort:  "*",
		DestCIDR:    "172.17.0.5/32",
		DestPort:    "23",
	}

	if err := r.Validate(); err != nil {
		t.Fatalf("valid rule failed validation: %v", err)
	}
	if r.dstPortMin != 23 || r.dstPortMax != 23 {
		t.Fatalf("expected dst port 23, got min=%d max=%d", r.dstPortMin, r.dstPortMax)
	}

	// Invalid rule ID
	r2 := r
	r2.ID = "invalid id with spaces!"
	if err := r2.Validate(); err == nil {
		t.Fatalf("expected error on invalid rule ID")
	}

	// Port range validation
	r3 := r
	r3.ID = "fw-rule-range"
	r3.DestPort = "8000-8080"
	if err := r3.Validate(); err != nil {
		t.Fatalf("port range validation failed: %v", err)
	}
	if r3.dstPortMin != 8000 || r3.dstPortMax != 8080 {
		t.Fatalf("expected 8000-8080, got %d-%d", r3.dstPortMin, r3.dstPortMax)
	}

	// Inverted port range
	r4 := r
	r4.ID = "fw-rule-bad-range"
	r4.DestPort = "8080-8000"
	if err := r4.Validate(); err == nil {
		t.Fatalf("expected error on inverted port range")
	}

	// Bad CIDR
	r5 := r
	r5.ID = "fw-rule-bad-cidr"
	r5.SourceCIDR = "999.999.999.999/99"
	if err := r5.Validate(); err == nil {
		t.Fatalf("expected error on malformed CIDR")
	}
}
