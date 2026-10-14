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
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestComposeHandler(mockContainers []docker.ContainerSummary, adminToken, viewerToken string) (*HandlerConfig, *httptest.Server) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/v1.43/containers/json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(mockContainers)
			return
		}
		if strings.Contains(path, "/restart") || strings.Contains(path, "/stop") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	client := docker.NewCustomClient(ts.Client(), ts.URL)
	var tokenAuth *security.TokenAuth
	if adminToken != "" || viewerToken != "" {
		tokenAuth = security.NewTokenAuth(adminToken, viewerToken, false)
	}

	mux := http.NewServeMux()
	cfg := RegisterRoutesWithSecurity(mux, client, nil, tokenAuth, false)
	cfg.AuditLogger = audit.NewLogger(100)

	return cfg, ts
}

func TestHandleComposeStacks(t *testing.T) {
	mockContainers := []docker.ContainerSummary{
		{
			ID:     "c10101010101",
			Names:  []string{"/infra-redis-1"},
			Image:  "redis:7-alpine",
			State:  "running",
			Status: "Up 3 hours",
			Labels: map[string]string{
				"com.docker.compose.project": "infra-stack",
				"com.docker.compose.service": "redis",
			},
		},
		{
			ID:     "c20202020202",
			Names:  []string{"/infra-postgres-1"},
			Image:  "postgres:16-alpine",
			State:  "running",
			Status: "Up 3 hours",
			Labels: map[string]string{
				"com.docker.compose.project": "infra-stack",
				"com.docker.compose.service": "postgres",
			},
		},
		{
			ID:     "c30303030303",
			Names:  []string{"/app-web-1"},
			Image:  "node:20-alpine",
			State:  "running",
			Status: "Up 1 hour",
			Labels: map[string]string{
				"com.docker.compose.project": "app-stack",
				"com.docker.compose.service": "web",
			},
		},
	}

	cfg, ts := setupTestComposeHandler(mockContainers, "", "")
	defer ts.Close()

	t.Run("GET /api/docker/compose returns all stacks", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/docker/compose", nil)
		rec := httptest.NewRecorder()

		cfg.handleComposeStacks(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp ComposeStacksResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.Count != 2 {
			t.Fatalf("expected 2 compose stacks, got %d", resp.Count)
		}
	})

	t.Run("GET /api/docker/compose with project filter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/docker/compose?project=app-stack", nil)
		rec := httptest.NewRecorder()

		cfg.handleComposeStacks(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}

		var resp ComposeStacksResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.Count != 1 || resp.Stacks[0].Project != "app-stack" {
			t.Fatalf("unexpected filtered response: %+v", resp)
		}
	})

	t.Run("Method Not Allowed for POST", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/docker/compose", nil)
		rec := httptest.NewRecorder()

		cfg.handleComposeStacks(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 Method Not Allowed, got %d", rec.Code)
		}
	})
}

func TestHandleComposeAction(t *testing.T) {
	mockContainers := []docker.ContainerSummary{
		{
			ID:     "c10101010101",
			Names:  []string{"/infra-redis-1"},
			Image:  "redis:7-alpine",
			State:  "running",
			Status: "Up 3 hours",
			Labels: map[string]string{
				"com.docker.compose.project": "infra-stack",
				"com.docker.compose.service": "redis",
			},
		},
	}

	cfg, ts := setupTestComposeHandler(mockContainers, "admin-secret-token", "viewer-secret-token")
	defer ts.Close()

	t.Run("POST /api/docker/compose/action restart with admin token", func(t *testing.T) {
		payload := ComposeActionRequest{
			Project: "infra-stack",
			Action:  "restart",
		}
		data, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/docker/compose/action", bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer admin-secret-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		cfg.handleComposeAction(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp ComposeActionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if !resp.Success || resp.Action != "restart" || resp.Project != "infra-stack" {
			t.Fatalf("unexpected response: %+v", resp)
		}
	})

	t.Run("POST /api/docker/compose/action stop with admin token", func(t *testing.T) {
		payload := ComposeActionRequest{
			Project: "infra-stack",
			Action:  "stop",
		}
		data, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/docker/compose/action", bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer admin-secret-token")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		cfg.handleComposeAction(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp ComposeActionResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if !resp.Success || resp.Action != "stop" {
			t.Fatalf("unexpected stop response: %+v", resp)
		}
	})

	t.Run("Viewer token rejected with 403 Forbidden", func(t *testing.T) {
		payload := ComposeActionRequest{
			Project: "infra-stack",
			Action:  "restart",
		}
		data, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/docker/compose/action", bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer viewer-secret-token")
		rec := httptest.NewRecorder()

		cfg.handleComposeAction(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden, got %d", rec.Code)
		}
	})

	t.Run("Invalid action rejected with 400 Bad Request", func(t *testing.T) {
		payload := ComposeActionRequest{
			Project: "infra-stack",
			Action:  "destroy_everything",
		}
		data, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/docker/compose/action", bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer admin-secret-token")
		rec := httptest.NewRecorder()

		cfg.handleComposeAction(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
	})

	t.Run("Invalid project name rejected with 400 Bad Request", func(t *testing.T) {
		payload := ComposeActionRequest{
			Project: "bad/project$name",
			Action:  "restart",
		}
		data, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/docker/compose/action", bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer admin-secret-token")
		rec := httptest.NewRecorder()

		cfg.handleComposeAction(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rec.Code)
		}
	})

	t.Run("Method Not Allowed for GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/docker/compose/action", nil)
		rec := httptest.NewRecorder()

		cfg.handleComposeAction(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 Method Not Allowed, got %d", rec.Code)
		}
	})
}
