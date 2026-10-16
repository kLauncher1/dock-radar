package ebpf

import (
	"testing"
	"time"
)

func TestSecurityEngine_EvaluateShellExec(t *testing.T) {
	rules := DefaultSecurityRules()
	engine := NewSecurityEngine(rules, 100, false, nil)

	event := SyscallEvent{
		ID:            "evt-1",
		Timestamp:     time.Now().UTC(),
		ContainerID:   "c-app",
		ContainerName: "payment-worker",
		PID:           1337,
		Syscall:       "execve",
		Comm:          "/bin/bash",
		Args:          []string{"-c", "id"},
	}

	alert := engine.Evaluate(event)
	if alert == nil {
		t.Fatal("Expected security alert for shell exec, got nil")
	}

	if alert.RuleID != "sec-rule-shell-exec" {
		t.Fatalf("Expected rule ID sec-rule-shell-exec, got %s", alert.RuleID)
	}
	if alert.Severity != SeverityHigh {
		t.Fatalf("Expected high severity, got %s", alert.Severity)
	}

	// Verify alert is recorded in recent alerts
	recent := engine.RecentAlerts(10, "", "")
	if len(recent) != 1 {
		t.Fatalf("Expected 1 recent alert, got %d", len(recent))
	}
}

func TestSecurityEngine_ContainerExclusion(t *testing.T) {
	rules := DefaultSecurityRules()
	// Add container exclusion for maintenance container
	for i := range rules {
		if rules[i].ID == "sec-rule-shell-exec" {
			rules[i].ExcludedContainers = []string{"debug-container"}
		}
	}

	engine := NewSecurityEngine(rules, 100, false, nil)

	event := SyscallEvent{
		ContainerID:   "debug-container",
		ContainerName: "debug-container",
		Syscall:       "execve",
		Comm:          "/bin/bash",
	}

	alert := engine.Evaluate(event)
	if alert != nil {
		t.Fatalf("Expected nil alert for excluded container, got alert %s", alert.ID)
	}
}

func TestSecurityEngine_SensitiveFileAccess(t *testing.T) {
	rules := DefaultSecurityRules()
	engine := NewSecurityEngine(rules, 100, false, nil)

	event := SyscallEvent{
		ContainerID:   "c-web",
		ContainerName: "web-server",
		Syscall:       "openat",
		Comm:          "cat",
		Args:          []string{"/etc/shadow"},
	}

	alert := engine.Evaluate(event)
	if alert == nil {
		t.Fatal("Expected alert for /etc/shadow read attempt")
	}
	if alert.RuleID != "sec-rule-sensitive-file" {
		t.Fatalf("Expected rule sec-rule-sensitive-file, got %s", alert.RuleID)
	}
	if alert.Severity != SeverityCritical {
		t.Fatalf("Expected critical severity, got %s", alert.Severity)
	}
}

func TestSecurityEngine_ToggleRule(t *testing.T) {
	rules := DefaultSecurityRules()
	engine := NewSecurityEngine(rules, 100, false, nil)

	err := engine.ToggleRule("sec-rule-shell-exec", false)
	if err != nil {
		t.Fatalf("Failed to disable rule: %v", err)
	}

	event := SyscallEvent{
		ContainerID: "c-app",
		Syscall:     "execve",
		Comm:        "/bin/sh",
	}

	alert := engine.Evaluate(event)
	if alert != nil {
		t.Fatalf("Expected nil alert when rule is disabled, got %s", alert.ID)
	}
}
