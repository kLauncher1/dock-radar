package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/mesh"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestMeshConfig(adminToken, viewerToken string) (*HandlerConfig, *http.ServeMux) {
	mux := http.NewServeMux()
	tokenAuth := security.NewTokenAuth(adminToken, viewerToken, true)
	cfg := &HandlerConfig{
		AuditLogger:  audit.NewLogger(100),
		MeshRegistry: mesh.NewRegistry("coordinator", "local-node"),
		TokenAuth:    tokenAuth,
		AllowRemote:  true,
		AppVersion:   "1.2.0",
	}

	mux.HandleFunc("/api/nodes", cfg.handleMeshNodes)
	mux.HandleFunc("/api/nodes/register", cfg.handleMeshNodes)
	mux.HandleFunc("/api/nodes/heartbeat", cfg.handleNodeHeartbeat)
	mux.HandleFunc("/api/cluster/summary", cfg.handleClusterSummary)
	mux.HandleFunc("/api/cluster/containers", cfg.handleClusterContainers)

	return cfg, mux
}

func TestMeshNodes_GetAndPost(t *testing.T) {
	cfg, mux := setupTestMeshConfig("admin-secret", "viewer-secret")

	// 1. Initial GET should return empty list (with Viewer token)
	getReq := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	getReq.Header.Set("Authorization", "Bearer viewer-secret")
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", getRec.Code)
	}

	var getResp struct {
		Nodes []*mesh.Node `json:"nodes"`
		Total int          `json:"total"`
	}
	_ = json.NewDecoder(getRec.Body).Decode(&getResp)
	if getResp.Total != 0 {
		t.Errorf("expected 0 nodes, got %d", getResp.Total)
	}

	// 2. POST without Admin token should be Forbidden
	postBody, _ := json.Marshal(NodeRegisterRequest{
		ID:      "worker-1",
		Name:    "Worker 1",
		Address: "http://10.0.0.10:9080",
		Labels:  map[string]string{"zone": "us-west"},
	})

	unauthPost := httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(postBody))
	unauthPost.Header.Set("Authorization", "Bearer viewer-secret") // only viewer, not admin
	unauthRec := httptest.NewRecorder()
	mux.ServeHTTP(unauthRec, unauthPost)

	if unauthRec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for viewer on POST, got %d", unauthRec.Code)
	}

	// 3. POST with Admin token should succeed
	adminPost := httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(postBody))
	adminPost.Header.Set("Authorization", "Bearer admin-secret")
	adminRec := httptest.NewRecorder()
	mux.ServeHTTP(adminRec, adminPost)

	if adminRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", adminRec.Code, adminRec.Body.String())
	}

	// Verify node is present in registry
	node, exists := cfg.MeshRegistry.Get("worker-1")
	if !exists || node.Name != "Worker 1" {
		t.Errorf("registered node not found in registry: %+v", node)
	}

	// 4. POST with invalid address should fail with 400
	badBody, _ := json.Marshal(NodeRegisterRequest{
		ID:      "bad-node",
		Address: "not-a-valid-url",
	})
	badReq := httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(badBody))
	badReq.Header.Set("Authorization", "Bearer admin-secret")
	badRec := httptest.NewRecorder()
	mux.ServeHTTP(badRec, badReq)

	if badRec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", badRec.Code)
	}
}

func TestMeshNodes_Delete(t *testing.T) {
	cfg, mux := setupTestMeshConfig("admin-secret", "viewer-secret")

	_ = cfg.MeshRegistry.Register(&mesh.Node{
		ID:      "node-to-delete",
		Name:    "Temporary Node",
		Address: "http://10.0.0.20:9080",
	})

	// DELETE without admin token -> 403
	delUnauth := httptest.NewRequest(http.MethodDelete, "/api/nodes?id=node-to-delete", nil)
	delUnauth.Header.Set("Authorization", "Bearer viewer-secret")
	recUnauth := httptest.NewRecorder()
	mux.ServeHTTP(recUnauth, delUnauth)

	if recUnauth.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", recUnauth.Code)
	}

	// DELETE with admin token -> 200
	delReq := httptest.NewRequest(http.MethodDelete, "/api/nodes?id=node-to-delete", nil)
	delReq.Header.Set("Authorization", "Bearer admin-secret")
	recOk := httptest.NewRecorder()
	mux.ServeHTTP(recOk, delReq)

	if recOk.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recOk.Code)
	}

	// DELETE non-existent node -> 404
	del404 := httptest.NewRequest(http.MethodDelete, "/api/nodes?id=nonexistent", nil)
	del404.Header.Set("Authorization", "Bearer admin-secret")
	rec404 := httptest.NewRecorder()
	mux.ServeHTTP(rec404, del404)

	if rec404.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found, got %d", rec404.Code)
	}
}

func TestClusterSummaryAndContainers(t *testing.T) {
	cfg, mux := setupTestMeshConfig("admin-secret", "viewer-secret")

	_ = cfg.MeshRegistry.Register(&mesh.Node{
		ID:      "edge-1",
		Name:    "Edge One",
		Address: "http://10.0.1.1:9080",
		Labels:  map[string]string{"env": "edge"},
	})

	cfg.MeshRegistry.UpdateNodeStatus("edge-1", mesh.NodeStatusOnline, 5, mesh.NodeMetrics{
		CPUPercent:        12.5,
		MemoryUsedBytes:   1024,
		ContainersRunning: 1,
		ContainersTotal:   2,
	}, []mesh.RemoteContainer{
		{ID: "c-active", State: "running", Names: []string{"/gateway"}},
		{ID: "c-idle", State: "exited", Names: []string{"/worker"}},
	}, "")

	// 1. Cluster Summary endpoint
	sumReq := httptest.NewRequest(http.MethodGet, "/api/cluster/summary", nil)
	sumReq.Header.Set("Authorization", "Bearer viewer-secret")
	sumRec := httptest.NewRecorder()
	mux.ServeHTTP(sumRec, sumReq)

	if sumRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", sumRec.Code)
	}

	var summary mesh.ClusterSummary
	_ = json.NewDecoder(sumRec.Body).Decode(&summary)
	if summary.TotalNodes != 1 || summary.OnlineNodes != 1 || summary.RunningContainers != 1 {
		t.Errorf("unexpected summary response: %+v", summary)
	}

	// 2. Cluster Containers endpoint with filter
	cntReq := httptest.NewRequest(http.MethodGet, "/api/cluster/containers?state=running", nil)
	cntReq.Header.Set("Authorization", "Bearer viewer-secret")
	cntRec := httptest.NewRecorder()
	mux.ServeHTTP(cntRec, cntReq)

	if cntRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", cntRec.Code)
	}

	var cntResp struct {
		Containers []mesh.RemoteContainer `json:"containers"`
		Total      int                    `json:"total"`
	}
	_ = json.NewDecoder(cntRec.Body).Decode(&cntResp)
	if cntResp.Total != 1 || cntResp.Containers[0].ID != "c-active" {
		t.Errorf("unexpected containers response: %+v", cntResp)
	}
}

func TestNodeHeartbeat(t *testing.T) {
	cfg, mux := setupTestMeshConfig("admin-secret", "viewer-secret")

	_ = cfg.MeshRegistry.Register(&mesh.Node{
		ID:      "agent-node",
		Address: "http://10.0.2.1:9080",
	})

	hbBody, _ := json.Marshal(NodeHeartbeatRequest{
		NodeID:    "agent-node",
		Status:    mesh.NodeStatusOnline,
		LatencyMs: 8,
		Metrics: mesh.NodeMetrics{
			CPUPercent: 33.3,
		},
		Containers: []mesh.RemoteContainer{
			{ID: "cnt-1", State: "running"},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/nodes/heartbeat", bytes.NewReader(hbBody))
	req.Header.Set("Authorization", "Bearer viewer-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	node, _ := cfg.MeshRegistry.Get("agent-node")
	if node.Status != mesh.NodeStatusOnline || node.LatencyMs != 8 {
		t.Errorf("node not updated after heartbeat: %+v", node)
	}
}
