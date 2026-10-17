package federation

import (
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
)

func TestEngine_LifecycleAndRegistration(t *testing.T) {
	cfg := DefaultFederationConfig()
	cfg.LocalRegionID = "us-east-1"
	cfg.LocalRegionName = "US East"
	cfg.TunnelKey = "my-test-federation-tunnel-key-32b"

	auditLogger := audit.NewLogger(100)
	alertStore := alert.NewConfigStore(alert.DefaultConfig())
	alertDisp := alert.NewDispatcher(alertStore)

	engine, err := NewEngine(cfg, nil, auditLogger, alertDisp)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	status := engine.GetStatus()
	if status.LocalRegionID != "us-east-1" || status.TotalRegions != 1 {
		t.Fatalf("unexpected initial status: %+v", status)
	}

	// Register remote region
	remoteRegion := &Region{
		ID:        "eu-west-1",
		Name:      "EU West (Ireland)",
		Endpoint:  "https://eu.dockradar.net",
		Latitude:  53.3,
		Longitude: -6.2,
	}
	if err := engine.RegisterRegion(remoteRegion); err != nil {
		t.Fatalf("failed to register remote region: %v", err)
	}

	status = engine.GetStatus()
	if status.TotalRegions != 2 || status.ActiveTunnels != 1 {
		t.Fatalf("expected 2 regions and 1 active tunnel, got regions=%d tunnels=%d", status.TotalRegions, status.ActiveTunnels)
	}

	// Test unregistering local region should fail
	if err := engine.UnregisterRegion("us-east-1"); err == nil {
		t.Fatal("expected error unregistering local region, got nil")
	}

	// Test unregistering remote region succeeds
	if err := engine.UnregisterRegion("eu-west-1"); err != nil {
		t.Fatalf("failed to unregister remote region: %v", err)
	}

	status = engine.GetStatus()
	if status.TotalRegions != 1 {
		t.Fatalf("expected 1 region after unregistration, got %d", status.TotalRegions)
	}
}

func TestEngine_SyncIngestRoundTrip(t *testing.T) {
	key := "shared-federation-cluster-secret-key"

	cfg1 := DefaultFederationConfig()
	cfg1.LocalRegionID = "region-a"
	cfg1.TunnelKey = key
	engineA, err := NewEngine(cfg1, nil, nil, nil)
	if err != nil {
		t.Fatalf("engineA creation failed: %v", err)
	}

	cfg2 := DefaultFederationConfig()
	cfg2.LocalRegionID = "region-b"
	cfg2.TunnelKey = key
	engineB, err := NewEngine(cfg2, nil, nil, nil)
	if err != nil {
		t.Fatalf("engineB creation failed: %v", err)
	}

	// Feed test containers into engine A
	engineA.SyncEngine().SetLocalContainers([]FederatedContainer{
		{ID: "c-101", Name: "billing-service", Image: "billing:latest", State: "running", RegionID: "region-a"},
		{ID: "c-102", Name: "payment-gateway", Image: "payment:latest", State: "running", RegionID: "region-a"},
	})

	// Generate delta on Engine A for Engine B
	deltaPayload, err := engineA.SyncEngine().ComputeDelta("region-b", "")
	if err != nil {
		t.Fatalf("compute delta failed: %v", err)
	}

	// Encrypt packet from A to B
	packet, err := engineA.TunnelManager().WrapPayload("region-b", deltaPayload)
	if err != nil {
		t.Fatalf("wrap payload failed: %v", err)
	}

	// Ingest into Engine B
	respPacket, err := engineB.IngestSyncPayload(packet)
	if err != nil {
		t.Fatalf("ingest sync payload failed: %v", err)
	}
	if respPacket == nil {
		t.Fatal("expected non-nil response packet from ingest")
	}

	// Verify Engine B now has containers from Region A
	containersInB := engineB.SyncEngine().GetRegionContainers("region-a")
	if len(containersInB) != 2 {
		t.Fatalf("expected 2 containers from region-a replicated to region-b, got %d", len(containersInB))
	}
}

func TestEngine_ConfigUpdates(t *testing.T) {
	cfg := DefaultFederationConfig()
	engine, err := NewEngine(cfg, nil, nil, nil)
	if err != nil {
		t.Fatalf("engine create failed: %v", err)
	}

	newCfg := engine.GetConfig()
	newCfg.SyncIntervalSec = 60
	newCfg.AutoFailoverEnabled = false

	if err := engine.UpdateConfig(newCfg); err != nil {
		t.Fatalf("update config failed: %v", err)
	}

	updated := engine.GetConfig()
	if updated.SyncIntervalSec != 60 || updated.AutoFailoverEnabled {
		t.Fatalf("config update not reflected: %+v", updated)
	}

	// Invalid config should fail
	invalidCfg := updated
	invalidCfg.SyncIntervalSec = 1
	if err := engine.UpdateConfig(invalidCfg); err == nil {
		t.Fatal("expected error on invalid config, got nil")
	}
}

func TestEngine_BackgroundStartAndStop(t *testing.T) {
	cfg := DefaultFederationConfig()
	cfg.SyncIntervalSec = 5
	engine, err := NewEngine(cfg, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		engine.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Clean exit
	case <-time.After(2 * time.Second):
		t.Fatal("engine.Start did not terminate within timeout")
	}
}
