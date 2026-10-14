package alert

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/system"
)

func TestContainerTracker_ExitTransition(t *testing.T) {
	tracker := NewContainerTracker()
	flappingWindow := 300 * time.Second
	restartThreshold := 3

	// Phase 1: Container starts as running
	batch1 := []docker.ContainerSummary{
		{
			ID:     "c111222333444",
			Names:  []string{"/web-api"},
			Image:  "golang:alpine",
			State:  "running",
			Status: "Up 10 minutes",
		},
	}
	events1 := tracker.EvaluateContainers(batch1, flappingWindow, restartThreshold)
	if len(events1) != 0 {
		t.Fatalf("expected 0 events on initial discovery, got %d", len(events1))
	}

	// Phase 2: Container crashes with non-zero exit code
	batch2 := []docker.ContainerSummary{
		{
			ID:     "c111222333444",
			Names:  []string{"/web-api"},
			Image:  "golang:alpine",
			State:  "exited",
			Status: "Exited (137) 2 seconds ago",
		},
	}
	events2 := tracker.EvaluateContainers(batch2, flappingWindow, restartThreshold)
	if len(events2) != 1 {
		t.Fatalf("expected 1 exit event, got %d", len(events2))
	}
	if events2[0].EventType != "container_exit" {
		t.Errorf("expected container_exit, got %s", events2[0].EventType)
	}
	if events2[0].Level != LevelCritical {
		t.Errorf("expected critical level for non-zero exit, got %s", events2[0].Level)
	}
}

func TestContainerTracker_RestartFlapping(t *testing.T) {
	tracker := NewContainerTracker()
	flappingWindow := 60 * time.Second
	restartThreshold := 3

	containerID := "c999888777666"

	// 1. Initial running
	tracker.EvaluateContainers([]docker.ContainerSummary{
		{ID: containerID, Names: []string{"/worker"}, State: "running", Status: "Up 1m"},
	}, flappingWindow, restartThreshold)

	// Simulate restart cycle 1
	tracker.EvaluateContainers([]docker.ContainerSummary{
		{ID: containerID, Names: []string{"/worker"}, State: "exited", Status: "Exited (1)"},
	}, flappingWindow, restartThreshold)
	eventsR1 := tracker.EvaluateContainers([]docker.ContainerSummary{
		{ID: containerID, Names: []string{"/worker"}, State: "running", Status: "Up 1s"},
	}, flappingWindow, restartThreshold)
	if len(eventsR1) != 0 {
		t.Errorf("cycle 1: expected 0 flapping events, got %d", len(eventsR1))
	}

	// Simulate restart cycle 2
	tracker.EvaluateContainers([]docker.ContainerSummary{
		{ID: containerID, Names: []string{"/worker"}, State: "exited", Status: "Exited (1)"},
	}, flappingWindow, restartThreshold)
	eventsR2 := tracker.EvaluateContainers([]docker.ContainerSummary{
		{ID: containerID, Names: []string{"/worker"}, State: "running", Status: "Up 1s"},
	}, flappingWindow, restartThreshold)
	if len(eventsR2) != 0 {
		t.Errorf("cycle 2: expected 0 flapping events, got %d", len(eventsR2))
	}

	// Simulate restart cycle 3 -> reaches restartThreshold 3!
	tracker.EvaluateContainers([]docker.ContainerSummary{
		{ID: containerID, Names: []string{"/worker"}, State: "exited", Status: "Exited (1)"},
	}, flappingWindow, restartThreshold)
	eventsR3 := tracker.EvaluateContainers([]docker.ContainerSummary{
		{ID: containerID, Names: []string{"/worker"}, State: "running", Status: "Up 1s"},
	}, flappingWindow, restartThreshold)

	if len(eventsR3) != 1 {
		t.Fatalf("cycle 3: expected 1 flapping event, got %d", len(eventsR3))
	}
	if eventsR3[0].EventType != "restart_flapping" {
		t.Errorf("expected restart_flapping, got %s", eventsR3[0].EventType)
	}
	if eventsR3[0].Level != LevelCritical {
		t.Errorf("expected critical severity for flapping, got %s", eventsR3[0].Level)
	}
}

func TestSystemTracker_Thresholds(t *testing.T) {
	st := NewSystemTracker()

	metrics := system.Metrics{
		Hostname:     "node-01",
		AllocMB:      600.0,
		SysMB:        800.0,
		NumCPU:       4,
		NumGoroutine: 12,
	}

	// 1. Under memory threshold (700 MB)
	events1 := st.EvaluateSystem(metrics, 85.0, 700.0)
	if len(events1) != 0 {
		t.Errorf("expected 0 events when under threshold, got %d", len(events1))
	}

	// 2. Over memory threshold (500 MB)
	events2 := st.EvaluateSystem(metrics, 85.0, 500.0)
	if len(events2) != 1 {
		t.Fatalf("expected 1 memory threshold event, got %d", len(events2))
	}
	if events2[0].EventType != "memory_threshold" {
		t.Errorf("expected memory_threshold, got %s", events2[0].EventType)
	}

	// 3. Over CPU threshold with explicit CPU
	events3 := st.EvaluateSystemWithCPU(metrics, 92.5, 80.0, 700.0)
	if len(events3) != 1 {
		t.Fatalf("expected 1 cpu threshold event, got %d", len(events3))
	}
	if events3[0].EventType != "cpu_threshold" {
		t.Errorf("expected cpu_threshold, got %s", events3[0].EventType)
	}
}

func TestMonitor_CheckOnceAndStart(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.43/containers/json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":"cabc12345678","names":["/test"],"image":"redis","state":"running","status":"Up 1h"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	dockerClient := docker.NewCustomClient(mockServer.Client(), mockServer.URL)
	configStore := NewConfigStore(DefaultConfig())
	dispatcher := NewDispatcher(configStore)
	monitor := NewMonitor(dockerClient, configStore, dispatcher)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initial sweep
	monitor.CheckOnce(ctx)

	// Verify monitor can start and stop gracefully
	done := make(chan struct{})
	go func() {
		defer close(done)
		monitor.Start(ctx, 20*time.Millisecond)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Clean exit
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("monitor.Start did not stop upon context cancellation")
	}
}
