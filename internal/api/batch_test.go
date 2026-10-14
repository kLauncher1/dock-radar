package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func TestHandleBatchAction_RestartAllAndAudit(t *testing.T) {
	// Mock Docker server responding to inspection and restart
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1.43/containers/json"):
			containers := []docker.ContainerSummary{
				{ID: "c1", Names: []string{"/web"}, State: "running"},
			}
			_ = json.NewEncoder(w).Encode(containers)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/restart"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := docker.NewCustomClient(server.Client(), server.URL)
	mux := http.NewServeMux()
	cfg := RegisterRoutesWithSecurity(mux, client, nil, nil, false)

	payload := []byte(`{"action":"restart_all","timeout":5}`)
	req := httptest.NewRequest(http.MethodPost, "/api/docker/batch", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:50000"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp BatchResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Success || resp.Action != "restart_all" {
		t.Errorf("unexpected response: %+v", resp)
	}

	// Verify Audit Logger recorded the event
	if cfg.AuditLogger == nil || cfg.AuditLogger.TotalCount() < 2 {
		t.Errorf("expected audit events to include batch_restart_all, count: %d", cfg.AuditLogger.TotalCount())
	}
	recent := cfg.AuditLogger.Recent(1, "batch_restart_all")
	if len(recent) != 1 || recent[0].Action != "batch_restart_all" {
		t.Errorf("expected audit entry for batch_restart_all, got %+v", recent)
	}
}

func TestHandleBatchAction_StopAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1.43/containers/json"):
			containers := []docker.ContainerSummary{
				{ID: "c1", Names: []string{"/db"}, State: "running"},
			}
			_ = json.NewEncoder(w).Encode(containers)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/stop"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := docker.NewCustomClient(server.Client(), server.URL)
	mux := http.NewServeMux()
	_ = RegisterRoutesWithSecurity(mux, client, nil, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/api/docker/batch?action=stop_all&timeout=3", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleBatchAction_Prune(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1.43/containers/prune" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ContainersDeleted": []string{"c_old"},
				"SpaceReclaimed":    2048,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := docker.NewCustomClient(server.Client(), server.URL)
	mux := http.NewServeMux()
	_ = RegisterRoutesWithSecurity(mux, client, nil, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/api/docker/batch?action=prune", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleBatchAction_AuthGuard(t *testing.T) {
	mux := http.NewServeMux()
	client := docker.NewCustomClient(nil, "http://127.0.0.1:59999")
	tokenAuth := security.NewTokenAuth("admin-secret", "viewer-secret", true)
	_ = RegisterRoutesWithSecurity(mux, client, nil, tokenAuth, true)

	// Viewer role cannot execute batch actions (RoleAdmin required)
	reqViewer := httptest.NewRequest(http.MethodPost, "/api/docker/batch?action=restart_all", nil)
	reqViewer.Header.Set("Authorization", "Bearer viewer-secret")
	rrViewer := httptest.NewRecorder()
	mux.ServeHTTP(rrViewer, reqViewer)

	if rrViewer.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for viewer on batch action, got %d", rrViewer.Code)
	}

	// Admin role is permitted
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/docker/batch?action=restart_all", nil)
	reqAdmin.Header.Set("Authorization", "Bearer admin-secret")
	rrAdmin := httptest.NewRecorder()
	mux.ServeHTTP(rrAdmin, reqAdmin)

	// Will proceed to daemon attempt (which fails gracefully with 500 or 502, not 401/403)
	if rrAdmin.Code == http.StatusUnauthorized || rrAdmin.Code == http.StatusForbidden {
		t.Errorf("admin was improperly denied access: %d", rrAdmin.Code)
	}
}

func TestHandleBatchAction_InvalidActionAndMethod(t *testing.T) {
	mux := http.NewServeMux()
	client := docker.NewCustomClient(nil, "http://127.0.0.1:59999")
	_ = RegisterRoutesWithSecurity(mux, client, nil, nil, false)

	// Method Not Allowed
	reqGet := httptest.NewRequest(http.MethodGet, "/api/docker/batch", nil)
	reqGet.RemoteAddr = "127.0.0.1:50000"
	rrGet := httptest.NewRecorder()
	mux.ServeHTTP(rrGet, reqGet)
	if rrGet.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rrGet.Code)
	}

	// Unsupported Action
	reqInvalid := httptest.NewRequest(http.MethodPost, "/api/docker/batch?action=destroy_universe", nil)
	reqInvalid.RemoteAddr = "127.0.0.1:50000"
	rrInvalid := httptest.NewRecorder()
	mux.ServeHTTP(rrInvalid, reqInvalid)
	if rrInvalid.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request on unknown action, got %d", rrInvalid.Code)
	}
}
