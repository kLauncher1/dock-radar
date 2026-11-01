package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/crash"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestCrashHandler(t *testing.T) (*HandlerConfig, *crash.Engine) {
	mux := http.NewServeMux()
	tokenAuth := security.NewTokenAuth("admin-secret-token", "viewer-secret-token", false)
	cfg := RegisterRoutesWithSecurity(mux, nil, nil, tokenAuth, false)
	return cfg, cfg.CrashEngine
}

func TestHandleCrashStatus_ViewerAccess(t *testing.T) {
	cfg, _ := setupTestCrashHandler(t)

	// Unauthorized request
	req := httptest.NewRequest(http.MethodGet, "/api/crash/status", nil)
	rr := httptest.NewRecorder()
	cfg.handleCrashStatus(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rr.Code)
	}

	// Authorized with viewer token
	req = httptest.NewRequest(http.MethodGet, "/api/crash/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	rr = httptest.NewRecorder()
	cfg.handleCrashStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	var status crash.CrashStatus
	if err := json.NewDecoder(rr.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode status response: %v", err)
	}
	if !status.Enabled {
		t.Errorf("expected crash pipeline to be enabled")
	}
}

func TestHandleCrashReports_CRUD(t *testing.T) {
	cfg, engine := setupTestCrashHandler(t)

	// Inject a test crash into engine
	rep, err := engine.TriggerTestCrash("container-alpha")
	if err != nil {
		t.Fatalf("TriggerTestCrash failed: %v", err)
	}

	// GET reports as viewer
	req := httptest.NewRequest(http.MethodGet, "/api/crash/reports?limit=10", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	rr := httptest.NewRecorder()
	cfg.handleCrashReports(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Reports []*crash.CrashReport `json:"reports"`
		Count   int                  `json:"count"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode reports response: %v", err)
	}
	if resp.Count != 1 || len(resp.Reports) != 1 {
		t.Errorf("expected 1 report, got count=%d, len=%d", resp.Count, len(resp.Reports))
	}
	if resp.Reports[0].ID != rep.ID {
		t.Errorf("expected report ID %s, got %s", rep.ID, resp.Reports[0].ID)
	}

	// GET detail
	req = httptest.NewRequest(http.MethodGet, "/api/crash/reports/detail?id="+rep.ID, nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	rr = httptest.NewRecorder()
	cfg.handleCrashReportDetail(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for detail, got %d", rr.Code)
	}

	var detail crash.CrashReport
	if err := json.NewDecoder(rr.Body).Decode(&detail); err != nil {
		t.Fatalf("failed to decode detail: %v", err)
	}
	if detail.ID != rep.ID || detail.ContainerID != "container-alpha" {
		t.Errorf("detail mismatch: ID=%s ContainerID=%s", detail.ID, detail.ContainerID)
	}

	// DELETE reports as admin
	req = httptest.NewRequest(http.MethodDelete, "/api/crash/reports", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	rr = httptest.NewRecorder()
	cfg.handleCrashReports(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for delete, got %d", rr.Code)
	}

	// Verify reports are cleared
	if len(engine.Reports(crash.ReportFilter{})) != 0 {
		t.Errorf("expected 0 reports after DELETE")
	}
}

func TestHandleCrashIngest_AndRBAC(t *testing.T) {
	cfg, _ := setupTestCrashHandler(t)

	tracePayload := `#0 0x00401142 in main () at server.c:42`
	reqBody, _ := json.Marshal(map[string]any{
		"container_id":   "c-app-99",
		"container_name": "app-backend",
		"image":          "app:v2",
		"raw_dump":       tracePayload,
	})

	// Viewer cannot ingest (requires Admin)
	req := httptest.NewRequest(http.MethodPost, "/api/crash/ingest", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	rr := httptest.NewRecorder()
	cfg.handleCrashIngest(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for viewer on ingest, got %d", rr.Code)
	}

	// Admin ingest
	req = httptest.NewRequest(http.MethodPost, "/api/crash/ingest", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	rr = httptest.NewRecorder()
	cfg.handleCrashIngest(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for admin ingest, got %d: %s", rr.Code, rr.Body.String())
	}

	var ingestResp struct {
		Status string             `json:"status"`
		Report *crash.CrashReport `json:"report"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&ingestResp); err != nil {
		t.Fatalf("failed to decode ingest response: %v", err)
	}
	if ingestResp.Status != "ingested" || ingestResp.Report.ContainerID != "c-app-99" {
		t.Errorf("unexpected ingest response: %+v", ingestResp)
	}
}

func TestHandleCrashTest_Drill(t *testing.T) {
	cfg, _ := setupTestCrashHandler(t)

	drillBody, _ := json.Marshal(map[string]string{
		"container_id": "drill-worker-02",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/crash/test", bytes.NewReader(drillBody))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	rr := httptest.NewRecorder()
	cfg.handleCrashTest(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for crash test drill, got %d: %s", rr.Code, rr.Body.String())
	}

	var testResp struct {
		Status string             `json:"status"`
		Report *crash.CrashReport `json:"report"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&testResp); err != nil {
		t.Fatalf("failed to decode drill response: %v", err)
	}
	if testResp.Status != "simulated" || testResp.Report.ContainerID != "drill-worker-02" {
		t.Errorf("unexpected test crash drill response: %+v", testResp)
	}
}

func TestHandleCrashConfig_GetAndPost(t *testing.T) {
	cfg, _ := setupTestCrashHandler(t)

	// GET config
	req := httptest.NewRequest(http.MethodGet, "/api/crash/config", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	rr := httptest.NewRecorder()
	cfg.handleCrashConfig(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET config, got %d", rr.Code)
	}

	// POST update config
	updateBody, _ := json.Marshal(crash.CrashConfig{
		Enabled:           true,
		WatchDirectory:    "data/custom_dump_dir",
		MaxReports:        300,
		RetentionDuration: 48 * 3600 * 1000000000,
		DedupWindow:       20 * 60 * 1000000000,
		AutoSymbolicate:   true,
		DispatchAlerts:    true,
		MaxCoreSizeBytes:  25 * 1024 * 1024,
	})

	req = httptest.NewRequest(http.MethodPost, "/api/crash/config", bytes.NewReader(updateBody))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	rr = httptest.NewRecorder()
	cfg.handleCrashConfig(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for POST config, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify update took effect
	c := cfg.CrashEngine.Config()
	if c.MaxReports != 300 || c.WatchDirectory != "data/custom_dump_dir" {
		t.Errorf("config update not reflected: %+v", c)
	}
}
