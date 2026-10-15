package mesh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGossipEngine_Initialization(t *testing.T) {
	reg := NewRegistry("local-1", "Local Coordinator")
	cfg := GossipConfig{}

	engine := NewGossipEngine("local-1", "Local Coordinator", "http://127.0.0.1:9080", reg, cfg)
	summary := engine.Summary()

	if summary.LocalID != "local-1" {
		t.Fatalf("expected local ID 'local-1', got '%s'", summary.LocalID)
	}
	if summary.Incarnation != 0 {
		t.Fatalf("expected incarnation 0, got %d", summary.Incarnation)
	}
	if summary.TotalMembers != 1 || summary.AliveMembers != 1 {
		t.Fatalf("expected 1 alive member (self), got total=%d alive=%d", summary.TotalMembers, summary.AliveMembers)
	}
}

func TestGossipEngine_ProcessPingAndACK(t *testing.T) {
	reg := NewRegistry("local-1", "Local Coordinator")
	cfg := GossipConfig{}
	engine := NewGossipEngine("local-1", "Local Coordinator", "http://127.0.0.1:9080", reg, cfg)

	ping := GossipMessage{
		Type:        "ping",
		SenderID:    "worker-1",
		SenderName:  "Worker 1",
		SenderAddr:  "http://192.168.1.10:9080",
		Incarnation: 1,
		Members: []GossipMemberDigest{
			{
				NodeID:      "worker-2",
				NodeName:    "Worker 2",
				Address:     "http://192.168.1.11:9080",
				State:       GossipStateAlive,
				Incarnation: 0,
			},
		},
		Timestamp: time.Now().Unix(),
	}

	ack := engine.ProcessIncomingMessage(ping)
	if ack == nil {
		t.Fatalf("expected non-nil ACK response to ping")
	}
	if ack.Type != "ack" {
		t.Fatalf("expected ACK type, got '%s'", ack.Type)
	}
	if ack.SenderID != "local-1" {
		t.Fatalf("expected sender ID 'local-1', got '%s'", ack.SenderID)
	}

	// Verify worker-1 and worker-2 are now tracked
	members := engine.Members()
	if len(members) != 3 {
		t.Fatalf("expected 3 members (self, worker-1, worker-2), got %d", len(members))
	}

	// Verify worker-2 was registered into Registry
	node, exists := reg.Get("worker-2")
	if !exists {
		t.Fatalf("expected worker-2 to be auto-registered in Registry")
	}
	if node.Name != "Worker 2" {
		t.Fatalf("expected name 'Worker 2', got '%s'", node.Name)
	}
}

func TestGossipEngine_IncarnationRefutation(t *testing.T) {
	reg := NewRegistry("local-1", "Local Coordinator")
	cfg := GossipConfig{}
	engine := NewGossipEngine("local-1", "Local Coordinator", "http://127.0.0.1:9080", reg, cfg)

	if engine.Incarnation() != 0 {
		t.Fatalf("expected initial incarnation 0")
	}

	// Another node falsely claims local-1 is Suspect with incarnation 0
	suspectMsg := GossipMessage{
		Type:        "ping",
		SenderID:    "worker-1",
		SenderName:  "Worker 1",
		SenderAddr:  "http://192.168.1.10:9080",
		Incarnation: 1,
		Members: []GossipMemberDigest{
			{
				NodeID:      "local-1",
				State:       GossipStateSuspect,
				Incarnation: 0,
			},
		},
	}

	ack := engine.ProcessIncomingMessage(suspectMsg)
	if ack == nil {
		t.Fatalf("expected ACK")
	}

	// Refutation: local-1 should have incremented incarnation to 1 and remained Alive
	if engine.Incarnation() != 1 {
		t.Fatalf("expected refuted incarnation 1, got %d", engine.Incarnation())
	}

	summary := engine.Summary()
	if summary.SuspectMembers != 0 {
		t.Fatalf("local node should not be in suspect state after refutation")
	}
}

func TestGossipEngine_PrecedenceRules(t *testing.T) {
	reg := NewRegistry("local-1", "Local Coordinator")
	cfg := GossipConfig{}
	engine := NewGossipEngine("local-1", "Local Coordinator", "http://127.0.0.1:9080", reg, cfg)

	_ = engine.AddMember(&GossipMember{
		NodeID:      "peer-1",
		NodeName:    "Peer 1",
		Address:     "http://10.0.0.1:9080",
		State:       GossipStateAlive,
		Incarnation: 2,
		LastSeen:    time.Now().UTC(),
	})

	// 1. Same incarnation: Suspect overrides Alive
	engine.ProcessIncomingMessage(GossipMessage{
		Type:       "ack",
		SenderID:   "peer-2",
		SenderAddr: "http://10.0.0.2:9080",
		Members: []GossipMemberDigest{
			{
				NodeID:      "peer-1",
				State:       GossipStateSuspect,
				Incarnation: 2,
			},
		},
	})

	for _, m := range engine.Members() {
		if m.NodeID == "peer-1" && m.State != GossipStateSuspect {
			t.Fatalf("expected peer-1 to become Suspect, got %s", m.State)
		}
	}

	// 2. Lower incarnation: Ignored
	engine.ProcessIncomingMessage(GossipMessage{
		Type:       "ack",
		SenderID:   "peer-2",
		SenderAddr: "http://10.0.0.2:9080",
		Members: []GossipMemberDigest{
			{
				NodeID:      "peer-1",
				State:       GossipStateAlive,
				Incarnation: 1, // Stale!
			},
		},
	})
	for _, m := range engine.Members() {
		if m.NodeID == "peer-1" && m.State != GossipStateSuspect {
			t.Fatalf("expected peer-1 to remain Suspect after stale incarnation, got %s", m.State)
		}
	}

	// 3. Higher incarnation: Overrides Suspect
	engine.ProcessIncomingMessage(GossipMessage{
		Type:       "ack",
		SenderID:   "peer-2",
		SenderAddr: "http://10.0.0.2:9080",
		Members: []GossipMemberDigest{
			{
				NodeID:      "peer-1",
				State:       GossipStateAlive,
				Incarnation: 3, // New incarnation!
			},
		},
	})
	for _, m := range engine.Members() {
		if m.NodeID == "peer-1" && m.State != GossipStateAlive {
			t.Fatalf("expected peer-1 to become Alive on higher incarnation, got %s", m.State)
		}
	}
}

func TestGossipEngine_SuspectWatchdogTimeout(t *testing.T) {
	reg := NewRegistry("local-1", "Local Coordinator")
	cfg := GossipConfig{
		SuspectTimeout: 50 * time.Millisecond,
	}
	engine := NewGossipEngine("local-1", "Local Coordinator", "http://127.0.0.1:9080", reg, cfg)

	_ = engine.AddMember(&GossipMember{
		NodeID:       "dying-node",
		NodeName:     "Dying Node",
		Address:      "http://10.0.0.5:9080",
		State:        GossipStateSuspect,
		Incarnation:  1,
		LastSeen:     time.Now().UTC(),
		SuspectSince: time.Now().UTC().Add(-60 * time.Millisecond),
	})

	engine.checkSuspects()

	var dyingState GossipState
	for _, m := range engine.Members() {
		if m.NodeID == "dying-node" {
			dyingState = m.State
		}
	}
	if dyingState != GossipStateDead {
		t.Fatalf("expected dying-node to transition to Dead, got %s", dyingState)
	}

	summary := engine.Summary()
	if summary.DeadMembers != 1 || summary.SuspectTimeouts != 1 {
		t.Fatalf("expected dead=1 suspect_timeouts=1, got dead=%d timeouts=%d", summary.DeadMembers, summary.SuspectTimeouts)
	}
}

func TestGossipEngine_DirectPingRoundTrip(t *testing.T) {
	reg := NewRegistry("local-1", "Local Coordinator")

	// Create mock peer HTTP server
	peerMux := http.NewServeMux()
	peerMux.HandleFunc("/api/mesh/gossip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"type": "ack",
			"sender_id": "remote-peer",
			"sender_name": "Remote Peer",
			"incarnation": 5,
			"members": [
				{"node_id": "remote-peer", "state": "alive", "incarnation": 5}
			]
		}`))
	})
	server := httptest.NewServer(peerMux)
	defer server.Close()

	cfg := GossipConfig{
		PingTimeout: 1 * time.Second,
	}
	engine := NewGossipEngine("local-1", "Local Coordinator", "http://127.0.0.1:9080", reg, cfg)
	_ = engine.AddMember(&GossipMember{
		NodeID:   "remote-peer",
		NodeName: "Remote Peer",
		Address:  server.URL,
		State:    GossipStateSuspect,
	})

	ctx := context.Background()
	ok, latency, ack := engine.sendPing(ctx, server.URL, "remote-peer")
	if !ok {
		t.Fatalf("expected ping to succeed")
	}
	if latency < 0 {
		t.Fatalf("expected non-negative latency, got %d", latency)
	}
	if ack == nil || ack.SenderID != "remote-peer" {
		t.Fatalf("expected ACK from remote-peer")
	}
}
