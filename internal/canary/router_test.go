package canary

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"
)

func TestTrafficRouter_WeightedDistribution(t *testing.T) {
	dep := &CanaryDeployment{
		ID:                  "test-canary-weights",
		BaselineContainerID: "cont-baseline-01",
		CanaryContainerID:   "cont-canary-02",
		Phase:               PhaseActive,
		Traffic: TrafficSplitConfig{
			BaselineWeight: 80,
			CanaryWeight:   20,
		},
	}

	router := NewTrafficRouter(dep, nil)

	totalRequests := 10000
	canaryCount := 0

	for i := 0; i < totalRequests; i++ {
		decision := router.Route(fmt.Sprintf("req-%d", i), nil)
		if decision.IsCanary {
			canaryCount++
			if decision.ContainerID != "cont-canary-02" {
				t.Fatalf("expected canary container ID cont-canary-02, got %s", decision.ContainerID)
			}
		} else {
			if decision.ContainerID != "cont-baseline-01" {
				t.Fatalf("expected baseline container ID cont-baseline-01, got %s", decision.ContainerID)
			}
		}
	}

	observedRatio := float64(canaryCount) / float64(totalRequests)
	expectedRatio := 0.20
	// 10,000 requests gives standard error ~0.004; allow 2.5% tolerance
	if math.Abs(observedRatio-expectedRatio) > 0.025 {
		t.Fatalf("expected canary ratio near %.2f, got observed %.4f (%d/%d)", expectedRatio, observedRatio, canaryCount, totalRequests)
	}
}

func TestTrafficRouter_HeaderOverride(t *testing.T) {
	dep := &CanaryDeployment{
		ID:                  "test-canary-override",
		BaselineContainerID: "cont-baseline-01",
		CanaryContainerID:   "cont-canary-02",
		Phase:               PhaseActive,
		Traffic: TrafficSplitConfig{
			BaselineWeight:       100,
			CanaryWeight:         0,
			CanaryHeaderOverride: "X-Canary-Force",
		},
	}

	router := NewTrafficRouter(dep, nil)

	// Normal request without header -> 100% baseline
	dec1 := router.Route("req-1", map[string]string{})
	if dec1.IsCanary {
		t.Fatalf("expected baseline target when no header override present")
	}

	// Request with override header -> 100% canary
	dec2 := router.Route("req-2", map[string]string{"X-Canary-Force": "true"})
	if !dec2.IsCanary || dec2.ContainerID != "cont-canary-02" {
		t.Fatalf("expected canary target with override header, got %s", dec2.ContainerID)
	}
	if dec2.Reason != "header_override_forced_canary" {
		t.Fatalf("expected reason header_override_forced_canary, got %s", dec2.Reason)
	}
}

func TestTrafficRouter_StickyAffinity(t *testing.T) {
	dep := &CanaryDeployment{
		ID:                  "test-canary-sticky",
		BaselineContainerID: "cont-base",
		CanaryContainerID:   "cont-can",
		Phase:               PhaseActive,
		Traffic: TrafficSplitConfig{
			BaselineWeight: 50,
			CanaryWeight:   50,
			HeaderAffinity: "X-User-ID",
		},
	}

	router := NewTrafficRouter(dep, nil)

	// For any given user ID, repeating the routing 100 times must return the EXACT same target
	testUsers := []string{"user-alice", "user-bob", "user-charlie", "user-dave", "user-eve"}
	for _, user := range testUsers {
		headers := map[string]string{"X-User-ID": user}
		firstDecision := router.Route("init", headers)
		for i := 0; i < 50; i++ {
			repeatDecision := router.Route(fmt.Sprintf("req-%d", i), headers)
			if repeatDecision.IsCanary != firstDecision.IsCanary {
				t.Fatalf("sticky affinity violation for user %s: first=%v, repeat=%v", user, firstDecision.IsCanary, repeatDecision.IsCanary)
			}
		}
	}
}

func TestTrafficRouter_PhaseFallback(t *testing.T) {
	dep := &CanaryDeployment{
		ID:                  "test-canary-fallback",
		BaselineContainerID: "cont-base",
		CanaryContainerID:   "cont-can",
		Phase:               PhaseRolledBack,
		Traffic: TrafficSplitConfig{
			BaselineWeight: 0,
			CanaryWeight:   100, // Even if weight is 100%, rolled back phase overrides to baseline
		},
	}

	router := NewTrafficRouter(dep, nil)
	dec := router.Route("req-fallback", nil)
	if dec.IsCanary || dec.ContainerID != "cont-base" {
		t.Fatalf("expected baseline on rolled back phase, got %s", dec.ContainerID)
	}

	// Update phase to completed
	router.UpdatePhase(PhaseCompleted)
	dec2 := router.Route("req-completed", nil)
	if !dec2.IsCanary || dec2.ContainerID != "cont-can" {
		t.Fatalf("expected canary on completed phase, got %s", dec2.ContainerID)
	}
}

func TestShadowMirror_LifecycleAndWorker(t *testing.T) {
	var mu sync.Mutex
	callbacks := 0

	cb := func(deploymentID string, statusCode int, duration time.Duration, isErr bool) {
		mu.Lock()
		callbacks++
		mu.Unlock()
	}

	cfg := ShadowMirrorConfig{
		Enabled:           true,
		SampleRate:        1.0,
		MaxQueueSize:      50,
		WorkerConcurrency: 2,
		TimeoutMs:         1000,
	}

	sm := NewShadowMirror(cfg, cb)
	defer sm.Stop()

	// Enqueue simulated jobs
	for i := 0; i < 10; i++ {
		ok := sm.Enqueue(ShadowJob{
			DeploymentID: "test-dep",
			RequestID:    fmt.Sprintf("shadow-req-%d", i),
			TargetURL:    "mock://canary-service",
			Method:       "GET",
		})
		if !ok {
			t.Fatalf("expected job %d to be enqueued", i)
		}
	}

	// Wait briefly for workers to process jobs
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	count := callbacks
	mu.Unlock()

	if count != 10 {
		t.Fatalf("expected 10 callback executions, got %d", count)
	}

	processed, dropped := sm.Stats()
	if processed != 10 {
		t.Fatalf("expected 10 processed jobs, got %d", processed)
	}
	if dropped != 0 {
		t.Fatalf("expected 0 dropped jobs, got %d", dropped)
	}
}
