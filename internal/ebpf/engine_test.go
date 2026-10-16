package ebpf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/docker"
)

func TestEngine_SampleOnceAndStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.43/containers/json" {
			containers := []docker.ContainerSummary{
				{
					ID:    "c-redis",
					Names: []string{"/redis-cache"},
					Image: "redis:7-alpine",
					State: "running",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(containers)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client := docker.NewCustomClient(ts.Client(), ts.URL)
	cfg := DefaultEBPFConfig()
	engine := NewEngine(cfg, client, nil, nil)

	engine.SampleOnce(context.Background())

	status := engine.Status()
	if !status.Enabled {
		t.Error("Expected engine to be enabled")
	}
	if status.ActiveFlows == 0 {
		t.Error("Expected active flows to be > 0 after sample")
	}
	if status.MonitoredContainers != 1 {
		t.Fatalf("Expected 1 monitored container, got %d", status.MonitoredContainers)
	}

	flows := engine.Flows(FlowFilter{ContainerID: "c-redis"})
	if len(flows) == 0 {
		t.Fatal("Expected flows for container c-redis, got 0")
	}

	// Verify Listen socket on 6379 exists
	foundListen := false
	for _, f := range flows {
		if f.State == "LISTEN" && f.LocalAddr == "0.0.0.0:6379" {
			foundListen = true
			break
		}
	}
	if !foundListen {
		t.Error("Expected LISTEN flow on 0.0.0.0:6379")
	}
}

func TestEngine_UpdateConfigAndReset(t *testing.T) {
	cfg := DefaultEBPFConfig()
	engine := NewEngine(cfg, nil, nil, nil)

	newCfg := cfg
	newCfg.SamplingIntervalSec = 5
	newCfg.MaxTrackedFlows = 5000

	err := engine.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("Failed to update config: %v", err)
	}

	updated := engine.GetConfig()
	if updated.SamplingIntervalSec != 5 || updated.MaxTrackedFlows != 5000 {
		t.Fatalf("Config not applied: %+v", updated)
	}

	// Add flow then reset
	engine.FlowTracker().RecordFlow(SocketFlow{
		ContainerID: "c-temp",
		Protocol:    "TCP",
		LocalAddr:   "127.0.0.1:80",
		RemoteAddr:  "127.0.0.1:4000",
		State:       "ESTABLISHED",
	})

	if len(engine.Flows(FlowFilter{})) != 1 {
		t.Fatal("Expected 1 flow before reset")
	}

	engine.Reset()

	if len(engine.Flows(FlowFilter{})) != 0 {
		t.Fatal("Expected 0 flows after reset")
	}
}

func TestEngine_Lifecycle(t *testing.T) {
	cfg := DefaultEBPFConfig()
	cfg.SamplingIntervalSec = 1
	engine := NewEngine(cfg, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(30 * time.Millisecond)

	engine.Stop()
}
