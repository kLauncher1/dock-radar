package firewall

import (
	"testing"

	"github.com/kLauncher1/dock-radar/internal/audit"
)

func TestEngine_InitializationAndDefaultRules(t *testing.T) {
	auditLogger := audit.NewLogger(100)
	engine := NewEngine(DefaultFirewallConfig(), nil, nil, auditLogger)

	status := engine.Status()
	if !status.Enabled {
		t.Fatalf("expected engine to be enabled")
	}
	if status.TotalRules < 3 {
		t.Fatalf("expected at least 3 default rules, got %d", status.TotalRules)
	}

	// Verify loopback rule exists
	r, ok := engine.GetRule("fw-def-loopback")
	if !ok || r.Action != ActionAllow {
		t.Fatalf("expected default loopback rule to exist with ALLOW")
	}
}

func TestEngine_EvaluatePacket_FullFlow(t *testing.T) {
	auditLogger := audit.NewLogger(100)
	engine := NewEngine(DefaultFirewallConfig(), nil, nil, auditLogger)

	// Add custom drop rule for Redis port 6379 from untrusted subnet
	err := engine.AddRule(FirewallRule{
		ID:         "block-redis-untrusted",
		Name:       "Block Untrusted Redis Access",
		Priority:   5,
		Enabled:    true,
		Direction:  DirectionIngress,
		Action:     ActionDrop,
		Protocol:   ProtocolTCP,
		SourceCIDR: "192.168.1.0/24",
		DestPort:   "6379",
	})
	if err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	// Test 1: Untrusted Redis packet -> DROP
	res1 := engine.EvaluatePacket(PacketPayload{
		SourceIP:      "192.168.1.50",
		DestIP:        "172.17.0.2",
		DestPort:      6379,
		Protocol:      ProtocolTCP,
		Direction:     DirectionIngress,
		PayloadLength: 100,
	})
	if res1.Action != ActionDrop || res1.MatchedRuleID != "block-redis-untrusted" {
		t.Fatalf("expected DROP on Redis rule, got %s", res1.Action)
	}

	// Test 2: Quarantine container c-bad, verify any packet from it is dropped
	engine.IsolateContainer("c-bad", "crypto-container", IsolationFullQuarantine, "Security containment", nil, 0, 0)
	res2 := engine.EvaluatePacket(PacketPayload{
		SourceContainerID: "c-bad",
		SourceIP:          "172.17.0.10",
		DestIP:            "8.8.8.8",
		DestPort:          53,
		Protocol:          ProtocolUDP,
		Direction:         DirectionEgress,
		PayloadLength:     64,
	})
	if res2.Action != ActionDrop || !res2.IsZeroTrustHit {
		t.Fatalf("expected DROP on quarantined container, got %s", res2.Action)
	}

	// Test 3: Status counters should reflect evaluations
	status := engine.Status()
	if status.TotalPacketsEvaluated != 2 {
		t.Fatalf("expected 2 evaluated packets, got %d", status.TotalPacketsEvaluated)
	}
	if status.TotalPacketsBlocked != 2 {
		t.Fatalf("expected 2 blocked packets, got %d", status.TotalPacketsBlocked)
	}
	if status.TotalBytesBlocked != 164 {
		t.Fatalf("expected 164 blocked bytes, got %d", status.TotalBytesBlocked)
	}
}

func TestEngine_IsolateAndUnisolate(t *testing.T) {
	auditLogger := audit.NewLogger(100)
	engine := NewEngine(DefaultFirewallConfig(), nil, nil, auditLogger)

	st := engine.IsolateContainer("c-db", "postgres-db", IsolationStrictZero, "Data tier protection", []string{"c-api"}, 5000000, 5000000)
	if st.ContainerID != "c-db" || st.IsolationLevel != IsolationStrictZero {
		t.Fatalf("isolation state mismatch: %+v", st)
	}

	isolations := engine.ListIsolations()
	if len(isolations) != 1 {
		t.Fatalf("expected 1 active isolation, got %d", len(isolations))
	}

	// Unisolate
	if !engine.UnisolateContainer("c-db") {
		t.Fatalf("failed to unisolate container")
	}
	if len(engine.ListIsolations()) != 0 {
		t.Fatalf("expected 0 active isolations after removal")
	}
}
