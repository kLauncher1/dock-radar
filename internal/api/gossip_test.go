package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/mesh"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func TestHandleMeshDiscovery_GetAndPost(t *testing.T) {
	reg := mesh.NewRegistry("local-node", "Local Coordinator")
	discCfg := mesh.DiscoveryConfig{
		Enabled:    true,
		NodeID:     "local-node",
		NodeName:   "Local Coordinator",
		Address:    "http://127.0.0.1:9080",
		ClusterKey: "test-cluster",
		Port:       19086,
	}
	discEngine := mesh.NewDiscoveryEngine(discCfg, reg)

	cfg := &HandlerConfig{
		MeshRegistry:  reg,
		MeshDiscovery: discEngine,
		AuditLogger:   audit.NewLogger(100),
		RateLimiter:   security.NewRateLimiter(10, 10),
	}

	// 1. GET /api/mesh/discovery
	req := httptest.NewRequest(http.MethodGet, "/api/mesh/discovery", nil)
	w := httptest.NewRecorder()
	cfg.handleMeshDiscovery(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", w.Code)
	}

	var status mesh.DiscoveryStatus
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to decode discovery status: %v", err)
	}
	if status.ClusterKey != "test-cluster" {
		t.Fatalf("expected cluster key 'test-cluster', got '%s'", status.ClusterKey)
	}

	// 2. POST /api/mesh/discovery/beacon
	postReq := httptest.NewRequest(http.MethodPost, "/api/mesh/discovery/beacon", nil)
	postReq.RemoteAddr = "127.0.0.1:45000"
	postW := httptest.NewRecorder()
	cfg.handleMeshDiscovery(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for beacon post, got %d", postW.Code)
	}

	var resp map[string]string
	_ = json.Unmarshal(postW.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", resp)
	}
}

func TestHandleMeshGossip_GetAndPost(t *testing.T) {
	reg := mesh.NewRegistry("local-node", "Local Coordinator")
	gossipEngine := mesh.NewGossipEngine("local-node", "Local Coordinator", "http://127.0.0.1:9080", reg, mesh.GossipConfig{})

	cfg := &HandlerConfig{
		MeshRegistry: reg,
		MeshGossip:   gossipEngine,
	}

	// 1. GET /api/mesh/gossip
	req := httptest.NewRequest(http.MethodGet, "/api/mesh/gossip", nil)
	w := httptest.NewRecorder()
	cfg.handleMeshGossip(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", w.Code)
	}

	var data struct {
		Summary mesh.GossipSummary   `json:"summary"`
		Members []mesh.GossipMember `json:"members"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("failed to unmarshal gossip response: %v", err)
	}
	if data.Summary.LocalID != "local-node" {
		t.Fatalf("expected local_id 'local-node', got '%s'", data.Summary.LocalID)
	}
	if len(data.Members) != 1 {
		t.Fatalf("expected 1 member (self), got %d", len(data.Members))
	}

	// 2. POST /api/mesh/gossip (peer ping)
	incoming := mesh.GossipMessage{
		Type:        "ping",
		SenderID:    "worker-node",
		SenderName:  "Worker Node",
		SenderAddr:  "http://192.168.1.55:9080",
		Incarnation: 1,
		Timestamp:   time.Now().Unix(),
	}
	payload, _ := json.Marshal(incoming)

	postReq := httptest.NewRequest(http.MethodPost, "/api/mesh/gossip", bytes.NewReader(payload))
	postW := httptest.NewRecorder()
	cfg.handleMeshGossip(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for gossip ping, got %d", postW.Code)
	}

	var ack mesh.GossipMessage
	if err := json.Unmarshal(postW.Body.Bytes(), &ack); err != nil {
		t.Fatalf("failed to unmarshal ACK: %v", err)
	}
	if ack.Type != "ack" || ack.SenderID != "local-node" {
		t.Fatalf("expected ACK from local-node, got %v", ack)
	}
}

func TestHandleMeshGossip_AuthGuard(t *testing.T) {
	reg := mesh.NewRegistry("local-node", "Local Coordinator")
	gossipEngine := mesh.NewGossipEngine("local-node", "Local Coordinator", "http://127.0.0.1:9080", reg, mesh.GossipConfig{})
	auth := security.NewTokenAuth("admin-secret-token-12345", "viewer-secret-token-67890", false)

	cfg := &HandlerConfig{
		MeshRegistry: reg,
		MeshGossip:   gossipEngine,
		TokenAuth:    auth,
	}

	// 1. Unauthenticated request should be rejected
	req := httptest.NewRequest(http.MethodGet, "/api/mesh/gossip", nil)
	w := httptest.NewRecorder()
	cfg.handleMeshGossip(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 Unauthorized, got %d", w.Code)
	}

	// 2. Authenticated with viewer token should pass
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/mesh/gossip", nil)
	reqAuth.Header.Set("Authorization", "Bearer viewer-secret-token-67890")
	wAuth := httptest.NewRecorder()
	cfg.handleMeshGossip(wAuth, reqAuth)

	if wAuth.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK with valid viewer token, got %d", wAuth.Code)
	}
}
