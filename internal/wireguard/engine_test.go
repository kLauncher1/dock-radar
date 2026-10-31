package wireguard

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
)

func TestEngine_AddAndGetPeer(t *testing.T) {
	logger := audit.NewLogger(100)
	cfg := DefaultWireGuardConfig()
	engine, err := NewEngine(cfg, logger, nil)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Stop()

	remotePeerKeys, _ := GenerateKeyPair()
	peerCfg := PeerConfig{
		ID:        "node-chicago",
		Name:      "Chicago Edge Gateway",
		PublicKey: remotePeerKeys.PublicKeyBase64,
		Endpoint:  "198.51.100.10:51820",
	}

	added, err := engine.AddPeer(peerCfg)
	if err != nil {
		t.Fatalf("AddPeer failed: %v", err)
	}

	if added.LeasedIP == "" {
		t.Errorf("expected automatic overlay IP lease to be assigned")
	}

	retrieved, found := engine.GetPeer("node-chicago")
	if !found {
		t.Fatalf("expected to find node-chicago")
	}
	if retrieved.ID != "node-chicago" {
		t.Errorf("expected ID node-chicago, got %s", retrieved.ID)
	}

	peers := engine.ListPeers()
	if len(peers) != 1 {
		t.Errorf("expected 1 peer, got %d", len(peers))
	}
}

func TestEngine_HandshakeAndSendReceive(t *testing.T) {
	logger := audit.NewLogger(100)
	cfgA := DefaultWireGuardConfig()
	cfgA.VirtualIP = "10.42.0.1"
	nodeA, err := NewEngine(cfgA, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Stop()

	cfgB := DefaultWireGuardConfig()
	cfgB.VirtualIP = "10.42.0.2"
	nodeB, err := NewEngine(cfgB, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Stop()

	// Register B on A
	peerB := PeerConfig{
		ID:        "node-b",
		Name:      "Node B",
		PublicKey: nodeB.Status().PublicKey,
		LeasedIP:  "10.42.0.2",
	}
	if _, err := nodeA.AddPeer(peerB); err != nil {
		t.Fatalf("nodeA AddPeer failed: %v", err)
	}

	// Register A on B
	peerA := PeerConfig{
		ID:        "node-a",
		Name:      "Node A",
		PublicKey: nodeA.Status().PublicKey,
		LeasedIP:  "10.42.0.1",
	}
	if _, err := nodeB.AddPeer(peerA); err != nil {
		t.Fatalf("nodeB AddPeer failed: %v", err)
	}

	// Explicit handshake on both sides
	if err := nodeA.InitiateHandshake("node-b"); err != nil {
		t.Fatalf("nodeA handshake failed: %v", err)
	}
	if err := nodeB.InitiateHandshake("node-a"); err != nil {
		t.Fatalf("nodeB handshake failed: %v", err)
	}

	// Construct packet from A (10.42.0.1) to B (10.42.0.2)
	payload := make([]byte, 25)
	payload[0] = 0x45 // IPv4
	copy(payload[12:16], []byte{10, 42, 0, 1})
	copy(payload[16:20], []byte{10, 42, 0, 2})
	copy(payload[20:], []byte("ping!"))

	encrypted, peerID, err := nodeA.SendPacket(net.ParseIP("10.42.0.2"), payload)
	if err != nil {
		t.Fatalf("SendPacket failed: %v", err)
	}
	if peerID != "node-b" {
		t.Errorf("expected routed peer node-b, got %s", peerID)
	}

	decrypted, err := nodeB.ReceivePacket("node-a", encrypted)
	if err != nil {
		t.Fatalf("ReceivePacket failed: %v", err)
	}
	if string(decrypted[20:]) != "ping!" {
		t.Errorf("expected decrypted payload ping!, got %s", string(decrypted[20:]))
	}
}

func TestEngine_RemovePeer(t *testing.T) {
	logger := audit.NewLogger(100)
	cfg := DefaultWireGuardConfig()
	engine, _ := NewEngine(cfg, logger, nil)
	defer engine.Stop()

	keys, _ := GenerateKeyPair()
	_, _ = engine.AddPeer(PeerConfig{
		ID:        "peer-delete",
		PublicKey: keys.PublicKeyBase64,
	})

	if !engine.RemovePeer("peer-delete") {
		t.Errorf("expected RemovePeer to succeed")
	}
	if _, found := engine.GetPeer("peer-delete"); found {
		t.Errorf("expected peer to be removed")
	}
}

func TestEngine_StatusAndConfig(t *testing.T) {
	logger := audit.NewLogger(100)
	cfg := DefaultWireGuardConfig()
	engine, _ := NewEngine(cfg, logger, nil)
	defer engine.Stop()

	st := engine.Status()
	if !st.Enabled || st.ListenPort != 51820 {
		t.Errorf("unexpected status: %+v", st)
	}

	liveCfg := engine.Config()
	if liveCfg.PrivateKey != "abcd....3456" && len(liveCfg.PrivateKey) > 16 {
		// Private key must be masked
		t.Errorf("private key was not properly masked: %s", liveCfg.PrivateKey)
	}
}

func TestEngine_Lifecycle(t *testing.T) {
	logger := audit.NewLogger(100)
	cfg := DefaultWireGuardConfig()
	engine, _ := NewEngine(cfg, logger, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := engine.Start(ctx); err != nil {
		t.Fatalf("engine.Start failed: %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	engine.Stop()
}
