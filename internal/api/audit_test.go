package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func TestHandleAuditExport_NDJSON(t *testing.T) {
	mux := http.NewServeMux()
	client := docker.NewCustomClient(nil, "http://127.0.0.1:59999")
	cfg := RegisterRoutesWithSecurity(mux, client, nil, nil, false)

	cfg.AuditLogger.Log(audit.AuditEvent{
		Action: "batch_restart_all",
		Target: "all_containers",
	})
	cfg.AuditLogger.Log(audit.AuditEvent{
		Action: "batch_prune",
		Target: "inactive_containers",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/audit/export", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/x-ndjson") {
		t.Errorf("expected Content-Type application/x-ndjson, got %s", contentType)
	}

	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 NDJSON lines, got %d", len(lines))
	}

	var ev audit.AuditEvent
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
		t.Fatalf("failed to decode last NDJSON event: %v", err)
	}
	if ev.Action != "batch_prune" {
		t.Errorf("expected last event action batch_prune, got %s", ev.Action)
	}
}

func TestHandleAuditExport_JSON(t *testing.T) {
	mux := http.NewServeMux()
	client := docker.NewCustomClient(nil, "http://127.0.0.1:59999")
	cfg := RegisterRoutesWithSecurity(mux, client, nil, nil, false)

	cfg.AuditLogger.Log(audit.AuditEvent{Action: "test_event", Target: "target1"})

	req := httptest.NewRequest(http.MethodGet, "/api/audit/export?format=json&action=test_event", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	var events []audit.AuditEvent
	if err := json.Unmarshal(rr.Body.Bytes(), &events); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	if len(events) != 1 || events[0].Action != "test_event" {
		t.Errorf("unexpected filtered events: %+v", events)
	}
}

func TestHandleAuditExport_AuthGuard(t *testing.T) {
	mux := http.NewServeMux()
	client := docker.NewCustomClient(nil, "http://127.0.0.1:59999")
	tokenAuth := security.NewTokenAuth("admin-secret", "viewer-secret", true)
	_ = RegisterRoutesWithSecurity(mux, client, nil, tokenAuth, true)

	// Unauthorized without token
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/audit/export", nil)
	rrUnauth := httptest.NewRecorder()
	mux.ServeHTTP(rrUnauth, reqUnauth)
	if rrUnauth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rrUnauth.Code)
	}

	// Authorized with viewer token
	reqViewer := httptest.NewRequest(http.MethodGet, "/api/audit/export", nil)
	reqViewer.Header.Set("Authorization", "Bearer viewer-secret")
	rrViewer := httptest.NewRecorder()
	mux.ServeHTTP(rrViewer, reqViewer)
	if rrViewer.Code != http.StatusOK {
		t.Errorf("expected 200 OK with viewer token, got %d", rrViewer.Code)
	}
}

func TestHandleAuditExport_MethodNotAllowed(t *testing.T) {
	mux := http.NewServeMux()
	client := docker.NewCustomClient(nil, "http://127.0.0.1:59999")
	_ = RegisterRoutesWithSecurity(mux, client, nil, nil, false)

	reqPost := httptest.NewRequest(http.MethodPost, "/api/audit/export", nil)
	rrPost := httptest.NewRecorder()
	mux.ServeHTTP(rrPost, reqPost)
	if rrPost.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed on POST /api/audit/export, got %d", rrPost.Code)
	}
}
