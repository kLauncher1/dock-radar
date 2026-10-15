package rolling

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/docker"
)

func TestReadinessProber_Success(t *testing.T) {
	var pollCount atomic.Int32

	// Mock Docker daemon server
	dockerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/json") {
			count := pollCount.Add(1)
			state := "running"
			status := "Up 5 seconds (healthy)"
			if count < 2 {
				status = "Up 1 second (health: starting)"
			}
			containers := []docker.ContainerSummary{
				{
					ID:     "c-100",
					Names:  []string{"/web-prod-1"},
					State:  state,
					Status: status,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(containers)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer dockerServer.Close()

	dClient := docker.NewCustomClient(dockerServer.Client(), dockerServer.URL)
	prober := NewReadinessProber(dClient, nil)

	cfg := RollingPlanConfig{
		ProbeTimeoutSec:   5,
		ProbeIntervalSec:  1,
		ReadinessGraceSec: 0,
	}

	ctx := context.Background()
	err := prober.WaitForReady(ctx, "c-100", cfg)
	if err != nil {
		t.Fatalf("WaitForReady() unexpected error: %v", err)
	}
}

func TestReadinessProber_UnhealthyAbort(t *testing.T) {
	dockerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		containers := []docker.ContainerSummary{
			{
				ID:     "c-bad",
				Names:  []string{"/web-bad"},
				State:  "running",
				Status: "Up 10 seconds (unhealthy)",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(containers)
	}))
	defer dockerServer.Close()

	dClient := docker.NewCustomClient(dockerServer.Client(), dockerServer.URL)
	prober := NewReadinessProber(dClient, nil)

	cfg := RollingPlanConfig{
		ProbeTimeoutSec:   3,
		ProbeIntervalSec:  1,
		ReadinessGraceSec: 0,
	}

	ctx := context.Background()
	err := prober.WaitForReady(ctx, "c-bad", cfg)
	if err == nil {
		t.Fatalf("expected error for unhealthy container, got nil")
	}
	if !strings.Contains(err.Error(), "unhealthy") {
		t.Fatalf("expected unhealthy error message, got: %v", err)
	}
}

func TestReadinessProber_HTTPProbe(t *testing.T) {
	// Mock HTTP health server
	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer healthServer.Close()

	// Extract port
	portStr := healthServer.URL[strings.LastIndex(healthServer.URL, ":")+1:]
	port, _ := strconv.Atoi(portStr)

	dockerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		containers := []docker.ContainerSummary{
			{
				ID:     "c-http",
				Names:  []string{"/web-http"},
				State:  "running",
				Status: "Up 10 seconds",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(containers)
	}))
	defer dockerServer.Close()

	dClient := docker.NewCustomClient(dockerServer.Client(), dockerServer.URL)
	prober := NewReadinessProber(dClient, healthServer.Client())

	cfg := RollingPlanConfig{
		ProbeTimeoutSec:    5,
		ProbeIntervalSec:   1,
		HTTPProbePort:      port,
		HTTPProbePath:      "/healthz",
		ExpectedHTTPStatus: 200,
		ReadinessGraceSec:  0,
	}

	ctx := context.Background()
	err := prober.WaitForReady(ctx, "c-http", cfg)
	if err != nil {
		t.Fatalf("WaitForReady with HTTP probe unexpected error: %v", err)
	}
}
