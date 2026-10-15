package rolling

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
)

func TestEngine_TargetResolution(t *testing.T) {
	containers := []docker.ContainerSummary{
		{
			ID:    "c1-app",
			Names: []string{"/app-prod-1"},
			State: "running",
			Labels: map[string]string{
				"com.docker.compose.project": "web-stack",
				"tier":                       "backend",
			},
		},
		{
			ID:    "c2-app",
			Names: []string{"/app-prod-2"},
			State: "running",
			Labels: map[string]string{
				"com.docker.compose.project": "web-stack",
				"tier":                       "backend",
			},
		},
		{
			ID:    "c3-db",
			Names: []string{"/db-prod"},
			State: "running",
			Labels: map[string]string{
				"com.docker.compose.project": "db-stack",
				"tier":                       "database",
			},
		},
	}

	eng := &Engine{}

	// Target by container ID
	res1 := eng.resolveTargets(containers, RollingPlanConfig{
		TargetType:   TargetContainers,
		ContainerIDs: []string{"c1-app"},
	})
	if len(res1) != 1 || res1[0].ID != "c1-app" {
		t.Fatalf("expected 1 container c1-app, got %d", len(res1))
	}

	// Target by compose stack
	res2 := eng.resolveTargets(containers, RollingPlanConfig{
		TargetType:  TargetComposeStack,
		TargetValue: "web-stack",
	})
	if len(res2) != 2 {
		t.Fatalf("expected 2 containers for web-stack, got %d", len(res2))
	}

	// Target by label
	res3 := eng.resolveTargets(containers, RollingPlanConfig{
		TargetType:  TargetLabel,
		TargetValue: "tier=database",
	})
	if len(res3) != 1 || res3[0].ID != "c3-db" {
		t.Fatalf("expected 1 container for tier=database, got %d", len(res3))
	}
}

func TestEngine_ExecutionLifecycle_Success(t *testing.T) {
	mockDocker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/json") {
			containers := []docker.ContainerSummary{
				{
					ID:     "c-prod-1",
					Names:  []string{"/web-1"},
					State:  "running",
					Status: "Up 10 seconds",
				},
				{
					ID:     "c-prod-2",
					Names:  []string{"/web-2"},
					State:  "running",
					Status: "Up 10 seconds",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(containers)
			return
		}

		if strings.Contains(r.URL.Path, "/restart") {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer mockDocker.Close()

	dClient := docker.NewCustomClient(mockDocker.Client(), mockDocker.URL)
	auditLog := audit.NewLogger(100)
	alertStore := alert.NewConfigStore(alert.DefaultConfig())
	alertDisp := alert.NewDispatcher(alertStore)

	eng := NewEngine(dClient, auditLog, alertDisp)

	cfg := RollingPlanConfig{
		TargetType:        TargetContainers,
		ContainerIDs:      []string{"c-prod-1", "c-prod-2"},
		BatchSize:         1,
		DrainTimeoutSec:   0,
		ProbeTimeoutSec:   3,
		ProbeIntervalSec:  1,
		ReadinessGraceSec: 0,
		AutoRollback:      true,
	}

	op, err := eng.StartOperation(context.Background(), cfg)
	if err != nil {
		t.Fatalf("StartOperation unexpected error: %v", err)
	}

	// Wait for background execution to complete
	deadline := time.Now().Add(5 * time.Second)
	var finalOp *RollingOperation
	for time.Now().Before(deadline) {
		curr, found := eng.Store().Get(op.ID)
		if found && (curr.Status == StatusCompleted || curr.Status == StatusFailed) {
			finalOp = curr
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if finalOp == nil || finalOp.Status != StatusCompleted {
		t.Fatalf("expected operation status completed, got: %+v", finalOp)
	}

	if finalOp.CompletedCount != 2 {
		t.Fatalf("expected 2 completed containers, got %d", finalOp.CompletedCount)
	}

	stats := eng.Stats()
	if stats.TotalContainersRestarted != 2 {
		t.Fatalf("expected stats total restarted 2, got %d", stats.TotalContainersRestarted)
	}
}

func TestEngine_AbortOperation(t *testing.T) {
	mockDocker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/json") {
			containers := []docker.ContainerSummary{
				{ID: "c-long-1", State: "running", Status: "Up 5 seconds"},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(containers)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockDocker.Close()

	dClient := docker.NewCustomClient(mockDocker.Client(), mockDocker.URL)
	eng := NewEngine(dClient, nil, nil)

	cfg := RollingPlanConfig{
		TargetType:       TargetContainers,
		ContainerIDs:     []string{"c-long-1"},
		BatchSize:        1,
		DrainTimeoutSec:  5, // Slow drain so we can abort
		ProbeTimeoutSec:  5,
		ProbeIntervalSec: 1,
	}

	op, err := eng.StartOperation(context.Background(), cfg)
	if err != nil {
		t.Fatalf("StartOperation error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	err = eng.AbortOperation(op.ID)
	if err != nil {
		t.Fatalf("AbortOperation error: %v", err)
	}

	abortedOp, _ := eng.Store().Get(op.ID)
	if abortedOp.Status != StatusAborted {
		t.Fatalf("expected status aborted, got %s", abortedOp.Status)
	}
}
