package rolling

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDrainController_DrainWithHook(t *testing.T) {
	var drainCalls atomic.Int32
	var undrainCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-Dock-Radar-Action")
		if action == "drain" {
			drainCalls.Add(1)
		} else if action == "undrain" {
			undrainCalls.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dc := NewDrainController(server.Client())
	cfg := RollingPlanConfig{
		DrainTimeoutSec: 0, // Instant for fast testing
		DrainHookURL:    server.URL,
	}

	progress := ContainerProgress{
		ContainerID:   "test-container-1",
		ContainerName: "test-app",
	}

	ctx := context.Background()
	err := dc.Drain(ctx, progress, cfg)
	if err != nil {
		t.Fatalf("Drain() unexpected error: %v", err)
	}

	if drainCalls.Load() != 1 {
		t.Fatalf("expected 1 drain hook call, got %d", drainCalls.Load())
	}

	err = dc.Undrain(ctx, progress, cfg)
	if err != nil {
		t.Fatalf("Undrain() unexpected error: %v", err)
	}

	if undrainCalls.Load() != 1 {
		t.Fatalf("expected 1 undrain hook call, got %d", undrainCalls.Load())
	}
}

func TestDrainController_DrainContextCancellation(t *testing.T) {
	dc := NewDrainController(nil)
	cfg := RollingPlanConfig{
		DrainTimeoutSec: 10,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := dc.Drain(ctx, ContainerProgress{ContainerID: "test-c"}, cfg)
	if err == nil {
		t.Fatalf("expected error on cancelled context, got nil")
	}
}
