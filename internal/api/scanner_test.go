package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/scanner"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestScannerHandler() (*HandlerConfig, *scanner.ScannerEngine) {
	engine := scanner.NewEngine(scanner.DefaultScannerConfig(), nil, nil, nil)
	cfg := &HandlerConfig{
		ScannerEngine: engine,
		AllowRemote:   true,
	}
	return cfg, engine
}

func TestHandleScannerStatus_ViewerAccess(t *testing.T) {
	cfg, engine := setupTestScannerHandler()
	ctx := context.Background()
	_, _ = engine.ScanImage(ctx, "alpine:3.18")

	req := httptest.NewRequest(http.MethodGet, "/api/scanner/status", nil)
	rr := httptest.NewRecorder()

	cfg.handleScannerStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ScannerStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status.TotalScannedImages != 1 {
		t.Errorf("expected 1 scanned image, got %d", resp.Status.TotalScannedImages)
	}
	if resp.GatingPolicy.FailOnSeverity == "" {
		t.Errorf("expected populated GatingPolicy")
	}
}

func TestHandleScannerReports_Filter(t *testing.T) {
	cfg, engine := setupTestScannerHandler()
	ctx := context.Background()
	_, _ = engine.ScanImage(ctx, "alpine:3.18")
	_, _ = engine.ScanImage(ctx, "ubuntu:22.04")

	req := httptest.NewRequest(http.MethodGet, "/api/scanner/reports?image=alpine", nil)
	rr := httptest.NewRecorder()

	cfg.handleScannerReports(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	var resp ScannerReportsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.TotalCount != 1 {
		t.Errorf("expected 1 alpine report, got %d", resp.TotalCount)
	}
}

func TestHandleScannerReport_GetAndNotFound(t *testing.T) {
	cfg, engine := setupTestScannerHandler()
	ctx := context.Background()
	report, _ := engine.ScanImage(ctx, "alpine:3.18")

	// 1. Success case
	req := httptest.NewRequest(http.MethodGet, "/api/scanner/report?id="+report.ID, nil)
	rr := httptest.NewRecorder()
	cfg.handleScannerReport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	// 2. 404 Not Found case
	req404 := httptest.NewRequest(http.MethodGet, "/api/scanner/report?id=nonexistent", nil)
	rr404 := httptest.NewRecorder()
	cfg.handleScannerReport(rr404, req404)

	if rr404.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found, got %d", rr404.Code)
	}
}

func TestHandleScannerScan_AdminOnly(t *testing.T) {
	tokenAuth := security.NewTokenAuth("admin-secret-token-12345", "viewer-secret-token-12345", true)
	cfg, _ := setupTestScannerHandler()
	cfg.TokenAuth = tokenAuth

	// Unauthorized attempt (no token)
	payload := []byte(`{"image": "alpine:3.18"}`)
	reqNoAuth := httptest.NewRequest(http.MethodPost, "/api/scanner/scan", bytes.NewReader(payload))
	rrNoAuth := httptest.NewRecorder()
	cfg.handleScannerScan(rrNoAuth, reqNoAuth)

	if rrNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rrNoAuth.Code)
	}

	// Viewer token attempt (forbidden for admin actions)
	reqViewer := httptest.NewRequest(http.MethodPost, "/api/scanner/scan", bytes.NewReader(payload))
	reqViewer.Header.Set("Authorization", "Bearer viewer-secret-token-12345")
	rrViewer := httptest.NewRecorder()
	cfg.handleScannerScan(rrViewer, reqViewer)

	if rrViewer.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for viewer role, got %d", rrViewer.Code)
	}

	// Admin token attempt (success)
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/scanner/scan", bytes.NewReader(payload))
	reqAdmin.Header.Set("Authorization", "Bearer admin-secret-token-12345")
	rrAdmin := httptest.NewRecorder()
	cfg.handleScannerScan(rrAdmin, reqAdmin)

	if rrAdmin.Code != http.StatusOK {
		t.Errorf("expected 200 OK for admin role, got %d: %s", rrAdmin.Code, rrAdmin.Body.String())
	}
}

func TestHandleScannerSBOM_SPDXAndCycloneDX(t *testing.T) {
	cfg, engine := setupTestScannerHandler()
	ctx := context.Background()
	report, _ := engine.ScanImage(ctx, "alpine:3.18")

	// 1. SPDX format
	reqSPDX := httptest.NewRequest(http.MethodGet, "/api/scanner/sbom?id="+report.ID+"&format=spdx", nil)
	rrSPDX := httptest.NewRecorder()
	cfg.handleScannerSBOM(rrSPDX, reqSPDX)

	if rrSPDX.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for SPDX, got %d: %s", rrSPDX.Code, rrSPDX.Body.String())
	}
	if !strings.Contains(rrSPDX.Header().Get("Content-Type"), "spdx+json") {
		t.Errorf("unexpected content type: %s", rrSPDX.Header().Get("Content-Type"))
	}

	// 2. CycloneDX format
	reqCDX := httptest.NewRequest(http.MethodGet, "/api/scanner/sbom?id="+report.ID+"&format=cyclonedx", nil)
	rrCDX := httptest.NewRecorder()
	cfg.handleScannerSBOM(rrCDX, reqCDX)

	if rrCDX.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for CycloneDX, got %d: %s", rrCDX.Code, rrCDX.Body.String())
	}
	if !strings.Contains(rrCDX.Header().Get("Content-Type"), "cyclonedx+json") {
		t.Errorf("unexpected content type: %s", rrCDX.Header().Get("Content-Type"))
	}
}

func TestHandleScannerGating_GetAndPost(t *testing.T) {
	cfg, _ := setupTestScannerHandler()

	// 1. GET gating policy
	reqGet := httptest.NewRequest(http.MethodGet, "/api/scanner/gating", nil)
	rrGet := httptest.NewRecorder()
	cfg.handleScannerGating(rrGet, reqGet)

	if rrGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on GET gating, got %d", rrGet.Code)
	}

	// 2. POST update policy
	newPolicy := `{"fail_on_severity":"CRITICAL","max_critical":1,"max_high":5}`
	reqPost := httptest.NewRequest(http.MethodPost, "/api/scanner/gating", strings.NewReader(newPolicy))
	reqPost.Header.Set("Content-Type", "application/json")
	reqPost.RemoteAddr = "127.0.0.1:50000"
	rrPost := httptest.NewRecorder()
	cfg.handleScannerGating(rrPost, reqPost)

	if rrPost.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on POST gating, got %d: %s", rrPost.Code, rrPost.Body.String())
	}

	// Verify changed
	if cfg.ScannerEngine.GetGatingPolicy().MaxCritical != 1 {
		t.Errorf("expected MaxCritical=1, got %d", cfg.ScannerEngine.GetGatingPolicy().MaxCritical)
	}
}
