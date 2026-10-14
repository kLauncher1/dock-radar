package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/logs"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func TestHandlePrometheusMetrics_Success(t *testing.T) {
	mux := http.NewServeMux()
	client := docker.NewCustomClient(nil, "http://127.0.0.1:59999")
	cfg := RegisterRoutesWithSecurity(mux, client, nil, nil, false)
	cfg.AppVersion = "1.1.0"

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") || !strings.Contains(contentType, "version=0.0.4") {
		t.Errorf("expected Prometheus content-type text/plain; version=0.0.4, got %s", contentType)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "dock_radar_build_info") {
		t.Errorf("missing dock_radar_build_info metric in /metrics output")
	}
	if !strings.Contains(body, "dock_radar_host_uptime_seconds") {
		t.Errorf("missing dock_radar_host_uptime_seconds in /metrics output")
	}
	if !strings.Contains(body, "dock_radar_docker_daemon_available") {
		t.Errorf("missing dock_radar_docker_daemon_available in /metrics output")
	}
	if !strings.Contains(body, "dock_radar_audit_events_total") {
		t.Errorf("missing dock_radar_audit_events_total in /metrics output")
	}
}

func TestHandlePrometheusMetrics_MethodNotAllowed(t *testing.T) {
	mux := http.NewServeMux()
	client := docker.NewCustomClient(nil, "http://127.0.0.1:59999")
	_ = RegisterRoutesWithSecurity(mux, client, nil, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected HTTP 405 on POST /metrics, got %d", rr.Code)
	}
}

func TestHandlePrometheusMetrics_AuthRole(t *testing.T) {
	mux := http.NewServeMux()
	client := docker.NewCustomClient(nil, "http://127.0.0.1:59999")
	tokenAuth := security.NewTokenAuth("admin-secret", "viewer-secret", true)
	cfg := RegisterRoutesWithSecurity(mux, client, nil, tokenAuth, true)
	cfg.AuditLogger = audit.NewLogger(10)
	cfg.LogBuffer = logs.NewRingBuffer(10)

	// Case 1: Unauthorized without token
	reqUnauth := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rrUnauth := httptest.NewRecorder()
	mux.ServeHTTP(rrUnauth, reqUnauth)
	if rrUnauth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rrUnauth.Code)
	}

	// Case 2: Authorized with viewer token
	reqViewer := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqViewer.Header.Set("Authorization", "Bearer viewer-secret")
	rrViewer := httptest.NewRecorder()
	mux.ServeHTTP(rrViewer, reqViewer)
	if rrViewer.Code != http.StatusOK {
		t.Errorf("expected 200 OK with viewer token, got %d", rrViewer.Code)
	}

	// Case 3: Authorized with admin token
	reqAdmin := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqAdmin.Header.Set("Authorization", "Bearer admin-secret")
	rrAdmin := httptest.NewRecorder()
	mux.ServeHTTP(rrAdmin, reqAdmin)
	if rrAdmin.Code != http.StatusOK {
		t.Errorf("expected 200 OK with admin token, got %d", rrAdmin.Code)
	}
}
