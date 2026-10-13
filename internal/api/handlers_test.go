package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/logs"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestServer() (*http.ServeMux, *httptest.Server) {
	// Create a mock Docker engine daemon server
	mockDaemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/v1.43/containers/json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":"c12345678901","names":["/web"],"image":"nginx:alpine","state":"running","status":"Up 2 hours"}]`))
			return
		}
		if path == "/v1.43/containers/c12345678901/restart" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if path == "/v1.43/containers/c12345678901/stop" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if path == "/v1.43/containers/c12345678901/logs" {
			w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
			_, _ = w.Write([]byte("2026-10-14T05:00:00Z web server ready\n"))
			return
		}
		if path == "/v1.43/containers/missing-id/restart" || path == "/v1.43/containers/missing-id/stop" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))

	dockerClient := docker.NewCustomClient(mockDaemon.Client(), mockDaemon.URL)
	mux := http.NewServeMux()
	RegisterRoutes(mux, dockerClient, nil)
	return mux, mockDaemon
}

func TestGetSystemMetrics(t *testing.T) {
	mux, mockDaemon := setupTestServer()
	defer mockDaemon.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	var data map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}
	if data["os"] == "" {
		t.Errorf("expected os field in response")
	}
}

func TestGetDockerStatus(t *testing.T) {
	mux, mockDaemon := setupTestServer()
	defer mockDaemon.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/docker", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	var status docker.DaemonStatus
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode daemon status: %v", err)
	}
	if !status.Available {
		t.Errorf("expected available to be true")
	}
	if status.TotalCount != 1 {
		t.Errorf("expected 1 container, got %d", status.TotalCount)
	}
}

func TestContainerRestartEndpoint(t *testing.T) {
	mux, mockDaemon := setupTestServer()
	defer mockDaemon.Close()

	// 1. Successful POST with JSON body
	body, _ := json.Marshal(ActionRequest{ID: "c12345678901", Timeout: 5})
	req := httptest.NewRequest(http.MethodPost, "/api/docker/restart", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode action response: %v", err)
	}
	if !resp.Success || resp.Action != "restart" {
		t.Errorf("unexpected response content: %+v", resp)
	}

	// 2. Query param fallback
	reqQuery := httptest.NewRequest(http.MethodPost, "/api/docker/restart?id=c12345678901", nil)
	reqQuery.RemoteAddr = "127.0.0.1:50000"
	recQuery := httptest.NewRecorder()
	mux.ServeHTTP(recQuery, reqQuery)
	if recQuery.Code != http.StatusOK {
		t.Fatalf("expected query parameter invocation to succeed, got %d", recQuery.Code)
	}

	// 3. Invalid container ID
	reqBadID := httptest.NewRequest(http.MethodPost, "/api/docker/restart?id=../escape", nil)
	reqBadID.RemoteAddr = "127.0.0.1:50000"
	recBadID := httptest.NewRecorder()
	mux.ServeHTTP(recBadID, reqBadID)
	if recBadID.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for bad ID, got %d", recBadID.Code)
	}

	// 4. Non-loopback forbidden
	reqRemote := httptest.NewRequest(http.MethodPost, "/api/docker/restart?id=c12345678901", nil)
	reqRemote.RemoteAddr = "10.10.10.10:50000"
	recRemote := httptest.NewRecorder()
	mux.ServeHTTP(recRemote, reqRemote)
	if recRemote.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 for remote address, got %d", recRemote.Code)
	}

	// 5. Container not found returns 404
	reqNotFound := httptest.NewRequest(http.MethodPost, "/api/docker/restart?id=missing-id", nil)
	reqNotFound.RemoteAddr = "127.0.0.1:50000"
	recNotFound := httptest.NewRecorder()
	mux.ServeHTTP(recNotFound, reqNotFound)
	if recNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected HTTP 404 for missing container, got %d", recNotFound.Code)
	}
}

func TestContainerStopEndpoint(t *testing.T) {
	mux, mockDaemon := setupTestServer()
	defer mockDaemon.Close()

	// Successful stop
	body, _ := json.Marshal(ActionRequest{ID: "c12345678901", Timeout: 5})
	req := httptest.NewRequest(http.MethodPost, "/api/docker/stop", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode action response: %v", err)
	}
	if !resp.Success || resp.Action != "stop" {
		t.Errorf("unexpected response content: %+v", resp)
	}
}

func TestRateLimitEnforcement(t *testing.T) {
	limiter := security.NewRateLimiter(1.0, 0.1) // 1 burst, 0.1/s refill
	dockerClient := docker.NewClient()
	mux := http.NewServeMux()
	cfg := &HandlerConfig{DockerClient: dockerClient, RateLimiter: limiter}
	mux.HandleFunc("/api/docker/restart", cfg.handleContainerRestart)

	// First request succeeds or reaches next check
	req1 := httptest.NewRequest(http.MethodPost, "/api/docker/restart?id=test-id", nil)
	req1.RemoteAddr = "127.0.0.1:50000"
	rec1 := httptest.NewRecorder()
	mux.ServeHTTP(rec1, req1)

	// Second immediate request must be 429 Too Many Requests
	req2 := httptest.NewRequest(http.MethodPost, "/api/docker/restart?id=test-id", nil)
	req2.RemoteAddr = "127.0.0.1:50000"
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected HTTP 429 on exhausted rate limit, got %d", rec2.Code)
	}
}

func TestContainerLogsEndpoint_JSONSnapshot(t *testing.T) {
	mux, mockDaemon := setupTestServer()
	defer mockDaemon.Close()

	// 1. Fetch system logs
	req := httptest.NewRequest(http.MethodGet, "/api/docker/logs?id=system", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	var systemEntries []logs.LogEntry
	if err := json.NewDecoder(rec.Body).Decode(&systemEntries); err != nil {
		t.Fatalf("failed to decode system log entries: %v", err)
	}
	if len(systemEntries) == 0 {
		t.Fatalf("expected at least 1 system log entry from boot")
	}

	// 2. Fetch container logs
	req2 := httptest.NewRequest(http.MethodGet, "/api/docker/logs?id=c12345678901&tail=50", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec2.Code)
	}

	var containerEntries []logs.LogEntry
	if err := json.NewDecoder(rec2.Body).Decode(&containerEntries); err != nil {
		t.Fatalf("failed to decode container log entries: %v", err)
	}
	if len(containerEntries) != 1 {
		t.Fatalf("expected 1 container log entry, got %d", len(containerEntries))
	}
	if containerEntries[0].Message != "web server ready" {
		t.Errorf("unexpected message: %s", containerEntries[0].Message)
	}
}

func TestContainerLogsEndpoint_InvalidID(t *testing.T) {
	mux, mockDaemon := setupTestServer()
	defer mockDaemon.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/docker/logs?id=../evil/path", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for path traversal ID, got %d", rec.Code)
	}
}

