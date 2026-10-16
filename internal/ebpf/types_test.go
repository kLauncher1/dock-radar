package ebpf

import (
	"testing"
)

func TestDefaultEBPFConfig_Validation(t *testing.T) {
	cfg := DefaultEBPFConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default config failed validation: %v", err)
	}

	if len(cfg.SecurityRules) == 0 {
		t.Fatal("Expected default security rules, got empty slice")
	}

	// Test boundary validation
	badCfg := cfg
	badCfg.SamplingIntervalSec = 0
	if err := badCfg.Validate(); err == nil {
		t.Error("Expected error for SamplingIntervalSec = 0")
	}

	badCfg = cfg
	badCfg.MaxTrackedFlows = 50
	if err := badCfg.Validate(); err == nil {
		t.Error("Expected error for MaxTrackedFlows < 100")
	}

	badCfg = cfg
	badCfg.SecurityRules = []SecurityRule{
		{
			ID:      "bad-regex",
			Pattern: "[invalid-regex(",
		},
	}
	if err := badCfg.Validate(); err == nil {
		t.Error("Expected error for invalid regex pattern in security rule")
	}
}

func TestSecurityRule_Matching(t *testing.T) {
	rules := DefaultSecurityRules()
	var shellRule *SecurityRule
	for i := range rules {
		if rules[i].ID == "sec-rule-shell-exec" {
			shellRule = &rules[i]
			break
		}
	}

	if shellRule == nil {
		t.Fatal("sec-rule-shell-exec rule not found")
	}

	if !shellRule.Matches("/bin/bash") {
		t.Error("Expected /bin/bash to match shell exec rule")
	}
	if !shellRule.Matches("/bin/sh") {
		t.Error("Expected /bin/sh to match shell exec rule")
	}
	if shellRule.Matches("/usr/bin/nginx") {
		t.Error("Expected /usr/bin/nginx NOT to match shell exec rule")
	}
}

func TestSecurityRule_DockerSocket(t *testing.T) {
	rules := DefaultSecurityRules()
	var sockRule *SecurityRule
	for i := range rules {
		if rules[i].ID == "sec-rule-docker-socket" {
			sockRule = &rules[i]
			break
		}
	}

	if sockRule == nil {
		t.Fatal("sec-rule-docker-socket rule not found")
	}

	if !sockRule.Matches("/var/run/docker.sock") {
		t.Error("Expected /var/run/docker.sock to match docker socket rule")
	}
	if sockRule.Matches("/var/log/app.log") {
		t.Error("Expected /var/log/app.log NOT to match docker socket rule")
	}
}
