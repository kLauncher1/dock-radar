package canary

import (
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
)

func TestEngine_CRUDAndLifecycle(t *testing.T) {
	auditLogger := audit.NewLogger(100)
	cfg := DefaultCanaryConfig()
	engine := NewEngine(cfg, auditLogger, nil)

	dep := CanaryDeployment{
		ID:                  "canary-payments-v2",
		Name:                "Payments Service v2 Canary",
		ServiceName:         "payments-api",
		BaselineContainerID: "cont-pay-v1",
		CanaryContainerID:   "cont-pay-v2",
		Traffic: TrafficSplitConfig{
			BaselineWeight: 90,
			CanaryWeight:   10,
		},
		Shadow: ShadowMirrorConfig{
			Enabled:           true,
			SampleRate:        1.0,
			MaxQueueSize:      100,
			WorkerConcurrency: 2,
		},
		Rollback: RollbackPolicy{
			AutoRollback:          true,
			MaxErrorRateDelta:     5.0,
			MaxLatencyP95Ratio:    1.5,
			MinSampleSize:         20,
			ConsecutiveViolations: 1,
		},
	}

	created, err := engine.CreateDeployment(dep)
	if err != nil {
		t.Fatalf("failed to create deployment: %v", err)
	}
	if created.Phase != PhaseActive {
		t.Fatalf("expected phase active, got %s", created.Phase)
	}

	// Duplicate create should fail
	_, err = engine.CreateDeployment(dep)
	if err != ErrDeploymentExists {
		t.Fatalf("expected ErrDeploymentExists, got %v", err)
	}

	// Retrieve
	fetched, err := engine.GetDeployment("canary-payments-v2")
	if err != nil {
		t.Fatalf("failed to get deployment: %v", err)
	}
	if fetched.Name != dep.Name {
		t.Fatalf("expected name %s, got %s", dep.Name, fetched.Name)
	}

	// List
	list := engine.ListDeployments()
	if len(list) != 1 {
		t.Fatalf("expected 1 deployment in list, got %d", len(list))
	}

	// Update Weight
	err = engine.UpdateWeight("canary-payments-v2", 25)
	if err != nil {
		t.Fatalf("failed to update weight: %v", err)
	}
	fetched2, _ := engine.GetDeployment("canary-payments-v2")
	if fetched2.Traffic.CanaryWeight != 25 || fetched2.Traffic.BaselineWeight != 75 {
		t.Fatalf("expected 75/25 weight, got %d/%d", fetched2.Traffic.BaselineWeight, fetched2.Traffic.CanaryWeight)
	}

	// Route traffic
	dec, err := engine.RouteTraffic("canary-payments-v2", "test-req-1", nil)
	if err != nil {
		t.Fatalf("failed to route traffic: %v", err)
	}
	if dec.ContainerID == "" {
		t.Fatalf("expected resolved container ID")
	}

	// Ingest sample
	err = engine.RecordSample("canary-payments-v2", "baseline", 200, 15*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to record sample: %v", err)
	}

	// Manual Promote
	err = engine.Promote("canary-payments-v2")
	if err != nil {
		t.Fatalf("failed to promote: %v", err)
	}
	fetchedPromoted, _ := engine.GetDeployment("canary-payments-v2")
	if fetchedPromoted.Phase != PhaseCompleted || fetchedPromoted.Traffic.CanaryWeight != 100 {
		t.Fatalf("expected completed phase at 100%%, got %s at %d%%", fetchedPromoted.Phase, fetchedPromoted.Traffic.CanaryWeight)
	}

	// Manual Rollback
	err = engine.Rollback("canary-payments-v2", "manual operator rollback")
	if err != nil {
		t.Fatalf("failed to rollback: %v", err)
	}
	fetchedRolledBack, _ := engine.GetDeployment("canary-payments-v2")
	if fetchedRolledBack.Phase != PhaseRolledBack || fetchedRolledBack.Traffic.CanaryWeight != 0 {
		t.Fatalf("expected rolled back phase at 0%%, got %s at %d%%", fetchedRolledBack.Phase, fetchedRolledBack.Traffic.CanaryWeight)
	}

	// Status check
	status := engine.Status()
	if status.TotalDeployments != 1 {
		t.Fatalf("expected total deployments 1, got %d", status.TotalDeployments)
	}

	// Delete
	err = engine.DeleteDeployment("canary-payments-v2")
	if err != nil {
		t.Fatalf("failed to delete deployment: %v", err)
	}
	_, err = engine.GetDeployment("canary-payments-v2")
	if err != ErrDeploymentNotFound {
		t.Fatalf("expected ErrDeploymentNotFound after deletion, got %v", err)
	}
}

func TestEngine_AutomatedRollbackOnDivergence(t *testing.T) {
	auditLogger := audit.NewLogger(100)
	cfg := DefaultCanaryConfig()
	cfg.EvaluationInterval = 50 * time.Millisecond
	engine := NewEngine(cfg, auditLogger, nil)

	dep := CanaryDeployment{
		ID:                  "auto-rollback-target",
		Name:                "Auto Rollback Test Service",
		ServiceName:         "auth-service",
		BaselineContainerID: "cont-auth-v1",
		CanaryContainerID:   "cont-auth-v2",
		Traffic: TrafficSplitConfig{
			BaselineWeight: 90,
			CanaryWeight:   10,
		},
		Rollback: RollbackPolicy{
			AutoRollback:          true,
			MaxErrorRateDelta:     5.0,
			MaxLatencyP95Ratio:    1.5,
			MinSampleSize:         20,
			ConsecutiveViolations: 1,
		},
	}

	_, err := engine.CreateDeployment(dep)
	if err != nil {
		t.Fatalf("failed to create deployment: %v", err)
	}

	// Inject baseline healthy telemetry (25 samples, 0% errors, 10ms)
	for i := 0; i < 25; i++ {
		_ = engine.RecordSample("auto-rollback-target", "baseline", 200, 10*time.Millisecond)
	}

	// Inject canary high error telemetry (25 samples, 500 status code = 100% errors)
	for i := 0; i < 25; i++ {
		_ = engine.RecordSample("auto-rollback-target", "canary", 500, 10*time.Millisecond)
	}

	// Verify report shows divergence
	report, err := engine.GetDivergenceReport("auto-rollback-target")
	if err != nil {
		t.Fatalf("failed to get report: %v", err)
	}
	if !report.Diverged {
		t.Fatalf("expected divergence on 100%% canary errors")
	}

	// Trigger single evaluation pass manually
	inst := engine.instances["auto-rollback-target"]
	engine.evaluateSingleDeployment(inst)

	// Verify deployment was autonomously rolled back
	rolledBackDep, _ := engine.GetDeployment("auto-rollback-target")
	if rolledBackDep.Phase != PhaseRolledBack {
		t.Fatalf("expected phase %s, got %s", PhaseRolledBack, rolledBackDep.Phase)
	}
	if rolledBackDep.Traffic.CanaryWeight != 0 {
		t.Fatalf("expected canary weight 0, got %d", rolledBackDep.Traffic.CanaryWeight)
	}
	if rolledBackDep.RolledBackAt == nil {
		t.Fatalf("expected RolledBackAt timestamp to be populated")
	}

	status := engine.Status()
	if status.TotalRollbacks != 1 {
		t.Fatalf("expected total rollbacks 1, got %d", status.TotalRollbacks)
	}
}

func TestEngine_LifecycleBackgroundLoop(t *testing.T) {
	cfg := DefaultCanaryConfig()
	cfg.EvaluationInterval = 20 * time.Millisecond
	engine := NewEngine(cfg, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	engine.Stop()
}
