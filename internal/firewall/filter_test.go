package firewall

import (
	"testing"
)

func TestPacketFilter_AddAndListRules(t *testing.T) {
	pf := NewPacketFilter(10, ActionAllow)

	r1 := FirewallRule{
		ID:         "r2",
		Name:       "Rule Priority 20",
		Priority:   20,
		Enabled:    true,
		Direction:  DirectionBoth,
		Action:     ActionDrop,
		Protocol:   ProtocolTCP,
		DestPort:   "8080",
	}
	r2 := FirewallRule{
		ID:         "r1",
		Name:       "Rule Priority 10",
		Priority:   10,
		Enabled:    true,
		Direction:  DirectionBoth,
		Action:     ActionAllow,
		Protocol:   ProtocolTCP,
		DestPort:   "80",
	}

	if err := pf.AddRule(r1); err != nil {
		t.Fatalf("failed to add r1: %v", err)
	}
	if err := pf.AddRule(r2); err != nil {
		t.Fatalf("failed to add r2: %v", err)
	}

	// Duplicate rule ID check
	if err := pf.AddRule(r1); err == nil {
		t.Fatalf("expected error on duplicate rule ID")
	}

	rules := pf.ListRules()
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	// Verify sorted by priority: r1 (10) then r2 (20)
	if rules[0].ID != "r1" || rules[1].ID != "r2" {
		t.Fatalf("rules not sorted properly: first=%s, second=%s", rules[0].ID, rules[1].ID)
	}
}

func TestPacketFilter_EvaluateMatching(t *testing.T) {
	pf := NewPacketFilter(10, ActionAllow)

	_ = pf.AddRule(FirewallRule{
		ID:          "block-ssh",
		Name:        "Block SSH from internal subnet",
		Priority:    5,
		Enabled:     true,
		Direction:   DirectionIngress,
		Action:      ActionDrop,
		Protocol:    ProtocolTCP,
		SourceCIDR:  "172.17.0.0/16",
		DestPort:    "22",
	})

	_ = pf.AddRule(FirewallRule{
		ID:          "allow-web",
		Name:        "Allow Web Traffic",
		Priority:    10,
		Enabled:     true,
		Direction:   DirectionIngress,
		Action:      ActionAllow,
		Protocol:    ProtocolTCP,
		DestPort:    "80",
	})

	// Test 1: SSH from 172.17.0.2 to port 22 should DROP
	res1 := pf.Evaluate(PacketPayload{
		SourceIP:      "172.17.0.2",
		DestIP:        "172.17.0.5",
		DestPort:      22,
		Protocol:      ProtocolTCP,
		Direction:     DirectionIngress,
		PayloadLength: 128,
	})
	if res1.Action != ActionDrop || res1.MatchedRuleID != "block-ssh" {
		t.Fatalf("expected DROP on block-ssh, got %s (rule: %s)", res1.Action, res1.MatchedRuleID)
	}

	// Test 2: Web to port 80 should ALLOW
	res2 := pf.Evaluate(PacketPayload{
		SourceIP:      "172.17.0.2",
		DestIP:        "172.17.0.5",
		DestPort:      80,
		Protocol:      ProtocolTCP,
		Direction:     DirectionIngress,
		PayloadLength: 256,
	})
	if res2.Action != ActionAllow || res2.MatchedRuleID != "allow-web" {
		t.Fatalf("expected ALLOW on allow-web, got %s (rule: %s)", res2.Action, res2.MatchedRuleID)
	}

	// Test 3: Traffic to port 443 with no match falls back to default action (ALLOW)
	res3 := pf.Evaluate(PacketPayload{
		SourceIP:      "172.17.0.2",
		DestIP:        "172.17.0.5",
		DestPort:      443,
		Protocol:      ProtocolTCP,
		Direction:     DirectionIngress,
		PayloadLength: 64,
	})
	if res3.Action != ActionAllow || res3.MatchedRuleID != "" {
		t.Fatalf("expected default ALLOW, got %s (rule: %s)", res3.Action, res3.MatchedRuleID)
	}

	// Check matched metrics
	rule, ok := pf.GetRule("block-ssh")
	if !ok || rule.MatchedPackets != 1 || rule.MatchedBytes != 128 {
		t.Fatalf("rule metric mismatch: matched_packets=%d, matched_bytes=%d", rule.MatchedPackets, rule.MatchedBytes)
	}
}

func TestPacketFilter_UpdateAndDeleteRule(t *testing.T) {
	pf := NewPacketFilter(10, ActionAllow)

	r := FirewallRule{
		ID:        "temp-rule",
		Name:      "Temporary Rule",
		Priority:  50,
		Enabled:   true,
		Direction: DirectionBoth,
		Action:    ActionDrop,
		Protocol:  ProtocolUDP,
		DestPort:  "53",
	}
	_ = pf.AddRule(r)

	// Update rule
	r.Priority = 5
	r.Action = ActionReject
	if err := pf.UpdateRule(r); err != nil {
		t.Fatalf("failed to update rule: %v", err)
	}

	updated, ok := pf.GetRule("temp-rule")
	if !ok || updated.Priority != 5 || updated.Action != ActionReject {
		t.Fatalf("expected updated rule with priority 5 and action REJECT")
	}

	// Delete rule
	if err := pf.DeleteRule("temp-rule"); err != nil {
		t.Fatalf("failed to delete rule: %v", err)
	}
	if _, ok := pf.GetRule("temp-rule"); ok {
		t.Fatalf("expected rule to be deleted")
	}
}
