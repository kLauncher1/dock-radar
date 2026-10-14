package healing

import (
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
)

func TestEngine_DetectOOMAndCrashLoopAndUnhealthy(t *testing.T) {
	cfg := DefaultPolicyConfig()
	ps := NewPolicyStore(cfg)
	history := NewHistoryBuffer(100)
	auditLog := audit.NewLogger(100)
	engine := NewRemediationEngine(nil, ps, history, auditLog)

	containers := []docker.ContainerSummary{
		{
			ID:     "c-oom-123456",
			Names:  []string{"/redis-cache"},
			Image:  "redis:7-alpine",
			State:  "exited",
			Status: "Exited (137) 5 seconds ago",
		},
		{
			ID:     "c-crash-234567",
			Names:  []string{"/web-service"},
			Image:  "my-app:v1",
			State:  "restarting",
			Status: "Restarting (1) 2 seconds ago",
		},
		{
			ID:     "c-healthy-345678",
			Names:  []string{"/postgres-db"},
			Image:  "postgres:16",
			State:  "running",
			Status: "Up 2 hours (healthy)",
		},
		{
			ID:     "c-unhealthy-456789",
			Names:  []string{"/api-gateway"},
			Image:  "traefik:v3",
			State:  "running",
			Status: "Up 30 minutes (unhealthy)",
		},
	}

	plans := engine.EvaluateContainers(containers)
	if len(plans) != 3 {
		t.Fatalf("Expected 3 remediation plans, got %d", len(plans))
	}

	planMap := make(map[string]RemediationPlan)
	for _, p := range plans {
		planMap[p.ContainerID] = p
	}

	if planMap["c-oom-123456"].Trigger != TriggerOOMKilled {
		t.Errorf("Expected c-oom-123456 to trigger oom_killed, got %s", planMap["c-oom-123456"].Trigger)
	}
	if planMap["c-crash-234567"].Trigger != TriggerCrashLoop {
		t.Errorf("Expected c-crash-234567 to trigger crash_loop, got %s", planMap["c-crash-234567"].Trigger)
	}
	if planMap["c-unhealthy-456789"].Trigger != TriggerHealthcheckFailed {
		t.Errorf("Expected c-unhealthy-456789 to trigger healthcheck_failed, got %s", planMap["c-unhealthy-456789"].Trigger)
	}
}

func TestEngine_ExcludedContainersAndBypass(t *testing.T) {
	cfg := DefaultPolicyConfig()
	cfg.ExcludedContainers = []string{"redis-cache"}
	ps := NewPolicyStore(cfg)
	engine := NewRemediationEngine(nil, ps, nil, nil)

	containers := []docker.ContainerSummary{
		{
			ID:     "c-oom-123456",
			Names:  []string{"/redis-cache"},
			State:  "exited",
			Status: "Exited (137) 2s ago",
		},
		{
			ID:     "c-bypass-789",
			Names:  []string{"/labeled-service"},
			State:  "exited",
			Status: "Exited (137) 2s ago",
			Labels: map[string]string{"dock-radar.healing": "false"},
		},
	}

	plans := engine.EvaluateContainers(containers)
	if len(plans) != 0 {
		t.Errorf("Expected 0 plans due to exclusions and labels, got %d", len(plans))
	}
}

func TestEngine_QuarantineCircuitBreaker(t *testing.T) {
	cfg := DefaultPolicyConfig()
	cfg.MaxAttempts = 2
	cfg.BaseBackoffSec = 1
	ps := NewPolicyStore(cfg)
	history := NewHistoryBuffer(100)
	engine := NewRemediationEngine(nil, ps, history, nil)

	plan := RemediationPlan{
		ContainerID:   "c-troubled",
		ContainerName: "troubled-app",
		Image:         "trouble:latest",
		Trigger:       TriggerCrashLoop,
		Reason:        "Crash loop test",
	}

	// 1st attempt
	engine.scheduleRemediation(plan, cfg)

	// Simulate immediate next failure
	engine.mu.Lock()
	st := engine.states["c-troubled"]
	st.BackoffUntil = time.Now().Add(-1 * time.Second) // clear backoff wait
	engine.mu.Unlock()

	// 2nd attempt
	engine.scheduleRemediation(plan, cfg)

	// Simulate next failure
	engine.mu.Lock()
	st.BackoffUntil = time.Now().Add(-1 * time.Second)
	engine.mu.Unlock()

	// 3rd attempt -> Should trigger Circuit Breaker / Quarantine
	engine.scheduleRemediation(plan, cfg)

	stats := engine.Stats()
	if len(stats.QuarantinedContainers) != 1 {
		t.Fatalf("Expected 1 quarantined container, got %d", len(stats.QuarantinedContainers))
	}

	if stats.QuarantinedContainers[0].ContainerID != "c-troubled" {
		t.Errorf("Expected quarantined container to be c-troubled, got %s", stats.QuarantinedContainers[0].ContainerID)
	}

	// Test Reset Container
	reset := engine.ResetContainer("troubled-app")
	if !reset {
		t.Errorf("Expected ResetContainer to succeed for troubled-app")
	}

	statsAfter := engine.Stats()
	if len(statsAfter.QuarantinedContainers) != 0 {
		t.Errorf("Expected 0 quarantined containers after reset, got %d", len(statsAfter.QuarantinedContainers))
	}
}
