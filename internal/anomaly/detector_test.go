package anomaly

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/docker"
)

func TestDetector_SampleOnceAndSummary(t *testing.T) {
	sampleCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.43/containers/json" {
			containers := []docker.ContainerSummary{
				{ID: "c-worker-1", Names: []string{"/worker-1"}, State: "running"},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(containers)
			return
		}

		if r.URL.Path == "/v1.43/containers/c-worker-1/stats" {
			sampleCount++
			// Simulate increasing memory
			memUsage := uint64(50000000 + sampleCount*5000000)
			resp := docker.RawContainerStatsResponse{
				Read: time.Now().UTC(),
				Name: "/worker-1",
				ID:   "c-worker-1",
				MemoryStats: docker.RawMemoryStats{
					Usage: memUsage,
					Limit: 100000000,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		http.NotFound(w, r)
	}))
	defer ts.Close()

	client := docker.NewCustomClient(ts.Client(), ts.URL)
	cfgStore := alert.NewConfigStore(alert.Config{})
	dispatcher := alert.NewDispatcher(cfgStore)

	detector := NewDetector(client, dispatcher)

	// Run 4 samples to establish linear regression trend
	for i := 0; i < 4; i++ {
		preds, err := detector.SampleOnce(context.Background())
		if err != nil {
			t.Fatalf("unexpected error sampling: %v", err)
		}
		if len(preds) != 1 {
			t.Fatalf("expected 1 prediction, got %d", len(preds))
		}
		time.Sleep(10 * time.Millisecond)
	}

	summary := detector.GetSummary()
	if summary.MonitoredContainers != 1 {
		t.Fatalf("expected 1 monitored container, got %d", summary.MonitoredContainers)
	}
	if summary.FastestGrowingName != "worker-1" {
		t.Fatalf("expected fastest growing name 'worker-1', got '%s'", summary.FastestGrowingName)
	}

	allPreds := detector.GetPredictions()
	if len(allPreds) != 1 {
		t.Fatalf("expected 1 prediction from GetPredictions, got %d", len(allPreds))
	}
	if allPreds[0].ContainerID != "c-worker-1" {
		t.Fatalf("expected container ID 'c-worker-1', got '%s'", allPreds[0].ContainerID)
	}
}

func TestDetector_Lifecycle(t *testing.T) {
	client := docker.NewCustomClient(nil, "http://localhost:9999")
	detector := NewDetector(client, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go detector.Start(ctx, 20*time.Millisecond)
	time.Sleep(50 * time.Millisecond)

	detector.Stop()
}
