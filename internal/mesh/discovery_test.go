package mesh

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDiscoveryEngine_Defaults(t *testing.T) {
	reg := NewRegistry("node-local", "Local Node")
	cfg := DiscoveryConfig{
		NodeID:  "node-local",
		Address: "http://127.0.0.1:9080",
	}

	engine := NewDiscoveryEngine(cfg, reg)
	status := engine.Status()

	if status.Port != DefaultDiscoveryPort {
		t.Fatalf("expected default port %d, got %d", DefaultDiscoveryPort, status.Port)
	}
	if status.ClusterKey != DefaultClusterKey {
		t.Fatalf("expected cluster key %s, got %s", DefaultClusterKey, status.ClusterKey)
	}
	if status.PeersCount != 0 {
		t.Fatalf("expected 0 peers initially, got %d", status.PeersCount)
	}
}

func TestDiscoveryEngine_HandleIncomingBeacon(t *testing.T) {
	reg := NewRegistry("node-local", "Local Node")
	cfg := DiscoveryConfig{
		Enabled:    true,
		NodeID:     "node-local",
		NodeName:   "Local Coordinator",
		Address:    "http://127.0.0.1:9080",
		ClusterKey: "test-cluster",
		Port:       9088,
		PeerTTL:    10 * time.Second,
	}

	engine := NewDiscoveryEngine(cfg, reg)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 9088}

	// 1. Self beacon should be ignored
	selfPkt := &BeaconPacket{
		Type:       "beacon",
		NodeID:     "node-local",
		Address:    "http://127.0.0.1:9080",
		ClusterKey: "test-cluster",
	}
	engine.handleIncomingBeacon(selfPkt, remoteAddr)
	if len(engine.DiscoveredPeers()) != 0 {
		t.Fatalf("expected self beacon to be discarded")
	}

	// 2. Mismatched cluster key should be ignored
	foreignPkt := &BeaconPacket{
		Type:       "beacon",
		NodeID:     "node-foreign",
		Address:    "http://192.168.1.101:9080",
		ClusterKey: "other-cluster",
	}
	engine.handleIncomingBeacon(foreignPkt, remoteAddr)
	if len(engine.DiscoveredPeers()) != 0 {
		t.Fatalf("expected foreign cluster beacon to be discarded")
	}

	// 3. Valid peer beacon should be registered and tracked
	validPkt := &BeaconPacket{
		Type:       "beacon",
		Version:    1,
		NodeID:     "node-remote-1",
		NodeName:   "Remote Worker 1",
		Address:    "http://192.168.1.102:9080",
		ClusterKey: "test-cluster",
		Timestamp:  time.Now().Unix(),
	}
	engine.handleIncomingBeacon(validPkt, remoteAddr)

	peers := engine.DiscoveredPeers()
	if len(peers) != 1 {
		t.Fatalf("expected 1 discovered peer, got %d", len(peers))
	}
	if peers[0].NodeID != "node-remote-1" {
		t.Fatalf("expected peer ID 'node-remote-1', got '%s'", peers[0].NodeID)
	}
	if peers[0].BeaconsCount != 1 {
		t.Fatalf("expected 1 beacon count, got %d", peers[0].BeaconsCount)
	}

	// Verify it auto-registered in the main Registry
	node, exists := reg.Get("node-remote-1")
	if !exists {
		t.Fatalf("expected peer to be auto-registered in mesh Registry")
	}
	if node.Name != "Remote Worker 1" {
		t.Fatalf("expected node name 'Remote Worker 1', got '%s'", node.Name)
	}
	if node.Labels["discovered"] != "lan-udp" {
		t.Fatalf("expected label discovered=lan-udp, got %v", node.Labels)
	}

	// 4. Second beacon from same peer increments count
	engine.handleIncomingBeacon(validPkt, remoteAddr)
	peers = engine.DiscoveredPeers()
	if peers[0].BeaconsCount != 2 {
		t.Fatalf("expected 2 beacons, got %d", peers[0].BeaconsCount)
	}
}

func TestDiscoveryEngine_SweepExpiredPeers(t *testing.T) {
	reg := NewRegistry("node-local", "Local Node")
	cfg := DiscoveryConfig{
		Enabled:    true,
		NodeID:     "node-local",
		Address:    "http://127.0.0.1:9080",
		ClusterKey: "test-cluster",
		PeerTTL:    50 * time.Millisecond,
	}

	engine := NewDiscoveryEngine(cfg, reg)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 9085}

	engine.handleIncomingBeacon(&BeaconPacket{
		Type:       "beacon",
		NodeID:     "node-expiring",
		Address:    "http://192.168.1.105:9080",
		ClusterKey: "test-cluster",
	}, remoteAddr)

	if len(engine.DiscoveredPeers()) != 1 {
		t.Fatalf("expected 1 peer before sweep")
	}

	// Wait past TTL
	time.Sleep(70 * time.Millisecond)
	engine.sweepExpiredPeers()

	if len(engine.DiscoveredPeers()) != 0 {
		t.Fatalf("expected 0 peers after TTL expiration sweep")
	}
}

func TestDiscoveryEngine_LifecycleAndBroadcast(t *testing.T) {
	reg := NewRegistry("node-local", "Local Node")
	cfg := DiscoveryConfig{
		Enabled:        true,
		NodeID:         "node-local",
		NodeName:       "Coordinator",
		Address:        "http://127.0.0.1:9080",
		ClusterKey:     "test-cluster",
		Port:           19085, // Use high port to prevent conflicts
		BeaconInterval: 100 * time.Millisecond,
		PeerTTL:        500 * time.Millisecond,
	}

	engine := NewDiscoveryEngine(cfg, reg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := engine.Start(ctx)
	if err != nil {
		t.Logf("UDP port binding skipped (environment restriction): %v", err)
		return
	}
	defer engine.Stop()

	// Verify broadcast invocation
	_ = engine.BroadcastBeacon()
	if engine.BeaconsSent() == 0 {
		t.Fatalf("expected beacons sent > 0")
	}

	status := engine.Status()
	if !status.Listening {
		t.Fatalf("expected discovery engine listening state to be true")
	}
}
