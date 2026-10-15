package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/rolling"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestRollingServer() (*httptest.Server, *rolling.Engine) {
	mux := http.NewServeMux()

	// Mock Docker daemon
	mockDocker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/json") {
			containers := []docker.ContainerSummary{
				{
					ID:     "c-app-1",
					Names:  []string{"/web-service-1"},
					State:  "running",
					Status: "Up 20 seconds",
					Labels: map[string]string{
						"com.docker.compose.project": "web-stack",
					},
				},
				{
					ID:     "c-app-2",
					Names:  []string{"/web-service-2"},
					State:  "running",
					Status: "Up 20 seconds",
					Labels: map[string]string{
						"com.docker.compose.project": "web-stack",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(containers)
			return
		}
		if strings.Contains(r.URL.Path, "/restart") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	dockerClient := docker.NewCustomClient(mockDocker.Client(), mockDocker.URL)
	auditLogger := audit.NewLogger(100)
	rollingEngine := rolling.NewEngine(dockerClient, auditLogger, nil)

	tokenAuth := security.NewTokenAuth("admin-secret-token", "viewer-secret-token", false)
	cfg := &HandlerConfig{
		DockerClient:  dockerClient,
		AuditLogger:   auditLogger,
		RollingEngine: rollingEngine,
		TokenAuth:     tokenAuth,
		AllowRemote:   true,
	}

	mux.HandleFunc("/api/rolling/start", cfg.handleRollingStart)
	mux.HandleFunc("/api/rolling/status", cfg.handleRollingStatus)
	mux.HandleFunc("/api/rolling/operations", cfg.handleRollingOperations)
	mux.HandleFunc("/api/rolling/abort", cfg.handleRollingAbort)

	server := httptest.NewServer(mux)
	return server, rollingEngine
}

func TestRollingEndpoints_StartAndStatus(t *testing.T) {
	server, _ := setupTestRollingServer()
	defer server.Close()

	// Test 1: Start with invalid method
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/rolling/start", nil)
	resp, err := server.Client().Do(req)
	if err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d", resp.StatusCode)
	}

	// Test 2: Start without token (unauthorized)
	bodyPayload := `{"target_type":"compose_stack","target_value":"web-stack","batch_size":1,"drain_timeout_sec":0,"probe_timeout_sec":3}`
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/api/rolling/start", strings.NewReader(bodyPayload))
	req.Header.Set("Content-Type", "application/json")
	resp, err = server.Client().Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized without token, got %d", resp.StatusCode)
	}

	// Test 3: Start with viewer token (forbidden, requires admin)
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/api/rolling/start", strings.NewReader(bodyPayload))
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err = server.Client().Do(req)
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden with viewer token, got %d", resp.StatusCode)
	}

	// Test 4: Start with admin token (success 202 Accepted)
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/api/rolling/start", strings.NewReader(bodyPayload))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err = server.Client().Do(req)
	if err != nil || resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted with admin token, got %d", resp.StatusCode)
	}

	var startRes RollingStartResponse
	_ = json.NewDecoder(resp.Body).Decode(&startRes)
	resp.Body.Close()

	if !startRes.Success || startRes.Operation == nil || startRes.Operation.ID == "" {
		t.Fatalf("expected valid started operation, got %+v", startRes)
	}
	opID := startRes.Operation.ID

	// Test 5: Get Status
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/api/rolling/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	resp, err = server.Client().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for status, got %d", resp.StatusCode)
	}
	var statusRes RollingStatusResponse
	_ = json.NewDecoder(resp.Body).Decode(&statusRes)
	resp.Body.Close()
	if statusRes.TotalRecorded < 1 {
		t.Fatalf("expected at least 1 total recorded operation, got %d", statusRes.TotalRecorded)
	}

	// Test 6: Query Operation by ID
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/api/rolling/operations?id="+opID, nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	resp, err = server.Client().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for operation query, got %d", resp.StatusCode)
	}
	var opDetail rolling.RollingOperation
	_ = json.NewDecoder(resp.Body).Decode(&opDetail)
	resp.Body.Close()
	if opDetail.ID != opID {
		t.Fatalf("expected operation ID %s, got %s", opID, opDetail.ID)
	}

	// Test 7: List Operations
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/api/rolling/operations?limit=10", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	resp, err = server.Client().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for operations list, got %d", resp.StatusCode)
	}
	var opsRes RollingOperationsResponse
	_ = json.NewDecoder(resp.Body).Decode(&opsRes)
	resp.Body.Close()
	if opsRes.Count < 1 {
		t.Fatalf("expected at least 1 operation in list, got %d", opsRes.Count)
	}
}

func TestRollingEndpoints_Abort(t *testing.T) {
	server, eng := setupTestRollingServer()
	defer server.Close()

	// Store a dummy operation in store
	dummyOp := &rolling.RollingOperation{
		ID:     "roll-dummy-abort",
		Status: rolling.StatusCompleted,
	}
	eng.Store().Save(dummyOp)

	// Test 1: Abort without token
	abortPayload, _ := json.Marshal(RollingAbortRequest{ID: "roll-dummy-abort"})
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/rolling/abort", bytes.NewReader(abortPayload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for abort, got %d", resp.StatusCode)
	}

	// Test 2: Abort with admin token on non-active operation (should return 409 Conflict)
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/api/rolling/abort", bytes.NewReader(abortPayload))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err = server.Client().Do(req)
	if err != nil || resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for non-active operation, got %d", resp.StatusCode)
	}
}
