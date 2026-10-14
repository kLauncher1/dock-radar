package mesh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestProber_ProbeNode_Success(t *testing.T) {
	var tokenReceived atomic.Value
	tokenReceived.Store("")

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenReceived.Store(r.Header.Get("Authorization"))

		switch r.URL.Path {
		case "/api/system":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"hostname":       "worker-prod-1",
				"num_goroutine":  38,
				"alloc_mb":       64,
				"sys_mb":         128,
				"uptime_seconds": 3600,
			})
		case "/api/docker":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"available":     true,
				"total_count":   2,
				"running_count": 2,
				"containers": []map[string]any{
					{
						"id":      "abc123456789",
						"names":   []string{"/web-proxy"},
						"image":   "nginx:latest",
						"status":  "Up 10 hours",
						"state":   "running",
						"created": 1700000000,
						"ports":   "80->80/tcp",
					},
					{
						"id":      "def987654321",
						"names":   []string{"/redis-cache"},
						"image":   "redis:alpine",
						"status":  "Up 5 hours",
						"state":   "running",
						"created": 1700005000,
						"ports":   "6379->6379/tcp",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()

	reg := NewRegistry("local", "coordinator")
	_ = reg.Register(&Node{
		ID:      "worker-1",
		Name:    "Worker One",
		Address: mockServer.URL,
	})

	prober := NewProber(reg, ProberConfig{
		Interval:   50 * time.Millisecond,
		Timeout:    1 * time.Second,
		HTTPClient: mockServer.Client(),
		Token:      "secret-mesh-token",
	})

	ctx := context.Background()
	prober.ProbeOnce(ctx)

	node, ok := reg.Get("worker-1")
	if !ok {
		t.Fatal("expected worker-1 to exist in registry")
	}

	if node.Status != NodeStatusOnline {
		t.Errorf("expected node status %s, got %s (error: %s)", NodeStatusOnline, node.Status, node.LastError)
	}
	if node.Metrics.Goroutines != 38 {
		t.Errorf("expected 38 goroutines, got %d", node.Metrics.Goroutines)
	}
	if node.Metrics.ContainersRunning != 2 {
		t.Errorf("expected 2 running containers, got %d", node.Metrics.ContainersRunning)
	}
	if len(node.Containers) != 2 {
		t.Fatalf("expected 2 remote containers, got %d", len(node.Containers))
	}
	if node.Containers[0].NodeName != "Worker One" {
		t.Errorf("expected node name Worker One, got %s", node.Containers[0].NodeName)
	}

	authVal, _ := tokenReceived.Load().(string)
	if authVal != "Bearer secret-mesh-token" {
		t.Errorf("expected Bearer token, got %q", authVal)
	}
}

func TestProber_ProbeNode_DegradedAndOffline(t *testing.T) {
	// Degraded server: system responds, but Docker daemon unavailable
	degradedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/system" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"hostname":       "worker-degraded",
				"num_goroutine":  15,
				"alloc_mb":       20,
				"sys_mb":         50,
				"uptime_seconds": 120,
			})
			return
		}
		if r.URL.Path == "/api/docker" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"available":     false,
				"total_count":   0,
				"running_count": 0,
				"containers":    []any{},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer degradedServer.Close()

	// Offline server: returns 500 on /api/system
	failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer failingServer.Close()

	reg := NewRegistry("local", "coordinator")
	_ = reg.Register(&Node{ID: "node-deg", Address: degradedServer.URL})
	_ = reg.Register(&Node{ID: "node-off", Address: failingServer.URL})

	prober := NewProber(reg, ProberConfig{
		Timeout:    1 * time.Second,
		HTTPClient: degradedServer.Client(),
	})

	prober.ProbeOnce(context.Background())

	nodeDeg, _ := reg.Get("node-deg")
	if nodeDeg.Status != NodeStatusDegraded {
		t.Errorf("expected status %s for degraded server, got %s", NodeStatusDegraded, nodeDeg.Status)
	}

	nodeOff, _ := reg.Get("node-off")
	if nodeOff.Status != NodeStatusOffline {
		t.Errorf("expected status %s for failing server, got %s", NodeStatusOffline, nodeOff.Status)
	}
	if nodeOff.LastError == "" {
		t.Error("expected non-empty last error for offline node")
	}
}

func TestProber_Lifecycle(t *testing.T) {
	reg := NewRegistry("local", "coordinator")
	prober := NewProber(reg, ProberConfig{
		Interval: 20 * time.Millisecond,
		Timeout:  100 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		prober.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	prober.Stop()

	select {
	case <-done:
		// Stopped cleanly
	case <-time.After(500 * time.Millisecond):
		t.Fatal("prober failed to stop within deadline")
	}
}
