package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/ebpf"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestEBPFHandler() (*HandlerConfig, *ebpf.Engine) {
	cfg := ebpf.DefaultEBPFConfig()
	engine := ebpf.NewEngine(cfg, nil, nil, nil)

	// Pre-seed a flow
	engine.FlowTracker().RecordFlow(ebpf.SocketFlow{
		ContainerID:   "c-api-test",
		ContainerName: "api-service",
		Protocol:      "TCP",
		LocalAddr:     "172.17.0.2:8080",
		RemoteAddr:    "10.0.0.1:45678",
		State:         "ESTABLISHED",
		BytesSent:     500,
		BytesRecv:     1000,
		LastSeen:      time.Now().UTC(),
	})

	// Pre-seed an alert
	engine.Security().Evaluate(ebpf.SyscallEvent{
		ContainerID:   "c-api-test",
		ContainerName: "api-service",
		PID:           1234,
		Syscall:       "execve",
		Comm:          "/bin/sh",
	})

	auth := security.NewTokenAuth("admin-secret-token", "viewer-secret-token", false)
	auditLog := audit.NewLogger(50)

	handlerCfg := &HandlerConfig{
		EBPFEngine:  engine,
		TokenAuth:   auth,
		AuditLogger: auditLog,
		AllowRemote: true,
	}

	return handlerCfg, engine
}

func TestHandleEBPFStatus(t *testing.T) {
	handler, _ := setupTestEBPFHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/ebpf/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w := httptest.NewRecorder()

	handler.handleEBPFStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var resp EBPFStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse status response: %v", err)
	}

	if !resp.Status.Enabled {
		t.Error("Expected eBPF status enabled to be true")
	}
	if resp.Status.ActiveFlows != 1 {
		t.Errorf("Expected 1 active flow, got %d", resp.Status.ActiveFlows)
	}
}

func TestHandleEBPFFlows(t *testing.T) {
	handler, _ := setupTestEBPFHandler()

	// 1. Query with container filter
	req := httptest.NewRequest(http.MethodGet, "/api/ebpf/flows?container_id=c-api-test", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w := httptest.NewRecorder()

	handler.handleEBPFFlows(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var resp EBPFFlowsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse flows response: %v", err)
	}

	if resp.TotalCount != 1 {
		t.Fatalf("Expected 1 flow, got %d", resp.TotalCount)
	}
	if resp.Flows[0].LocalAddr != "172.17.0.2:8080" {
		t.Errorf("Unexpected local addr: %s", resp.Flows[0].LocalAddr)
	}

	// 2. Query with non-matching state filter
	reqMismatch := httptest.NewRequest(http.MethodGet, "/api/ebpf/flows?state=TIME_WAIT", nil)
	reqMismatch.Header.Set("Authorization", "Bearer viewer-secret-token")
	wMismatch := httptest.NewRecorder()

	handler.handleEBPFFlows(wMismatch, reqMismatch)
	var respMismatch EBPFFlowsResponse
	_ = json.Unmarshal(wMismatch.Body.Bytes(), &respMismatch)
	if respMismatch.TotalCount != 0 {
		t.Fatalf("Expected 0 flows for TIME_WAIT, got %d", respMismatch.TotalCount)
	}
}

func TestHandleEBPFSecurityEvents(t *testing.T) {
	handler, _ := setupTestEBPFHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/ebpf/security/events?severity=high", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w := httptest.NewRecorder()

	handler.handleEBPFSecurityEvents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	var resp EBPFSecurityEventsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse events response: %v", err)
	}

	if resp.TotalCount != 1 {
		t.Fatalf("Expected 1 security alert, got %d", resp.TotalCount)
	}
	if resp.Events[0].RuleID != "sec-rule-shell-exec" {
		t.Errorf("Unexpected rule ID: %s", resp.Events[0].RuleID)
	}
}

func TestHandleEBPFSecurityRules_RBAC(t *testing.T) {
	handler, _ := setupTestEBPFHandler()

	// 1. Viewer cannot POST rules
	body := []byte(`{"rules": []}`)
	reqPostViewer := httptest.NewRequest(http.MethodPost, "/api/ebpf/security/rules", bytes.NewReader(body))
	reqPostViewer.Header.Set("Authorization", "Bearer viewer-secret-token")
	wPostViewer := httptest.NewRecorder()

	handler.handleEBPFSecurityRules(wPostViewer, reqPostViewer)
	if wPostViewer.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for viewer rule update, got %d", wPostViewer.Code)
	}

	// 2. Admin can toggle rule
	reqToggleAdmin := httptest.NewRequest(http.MethodPost, "/api/ebpf/security/rules?toggle=sec-rule-shell-exec&enabled=false", nil)
	reqToggleAdmin.Header.Set("Authorization", "Bearer admin-secret-token")
	wToggleAdmin := httptest.NewRecorder()

	handler.handleEBPFSecurityRules(wToggleAdmin, reqToggleAdmin)
	if wToggleAdmin.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for admin toggle, got %d (%s)", wToggleAdmin.Code, wToggleAdmin.Body.String())
	}

	// 3. Verify rule is disabled
	reqGet := httptest.NewRequest(http.MethodGet, "/api/ebpf/security/rules", nil)
	reqGet.Header.Set("Authorization", "Bearer viewer-secret-token")
	wGet := httptest.NewRecorder()

	handler.handleEBPFSecurityRules(wGet, reqGet)
	var rulesResp EBPFSecurityRulesResponse
	_ = json.Unmarshal(wGet.Body.Bytes(), &rulesResp)

	found := false
	for _, r := range rulesResp.Rules {
		if r.ID == "sec-rule-shell-exec" {
			found = true
			if r.Enabled {
				t.Error("Expected sec-rule-shell-exec to be disabled")
			}
			break
		}
	}
	if !found {
		t.Fatal("Rule sec-rule-shell-exec not found in response")
	}
}

func TestHandleEBPFReset_And_TriggerTest(t *testing.T) {
	handler, engine := setupTestEBPFHandler()

	// 1. Trigger test anomaly
	reqTrigger := httptest.NewRequest(http.MethodPost, "/api/ebpf/trigger-test?container_id=c-test&container_name=demo", nil)
	reqTrigger.Header.Set("Authorization", "Bearer admin-secret-token")
	wTrigger := httptest.NewRecorder()

	handler.handleEBPFTriggerTest(wTrigger, reqTrigger)
	if wTrigger.Code != http.StatusOK {
		t.Fatalf("Expected 200 for trigger-test, got %d", wTrigger.Code)
	}

	// 2. Reset
	reqReset := httptest.NewRequest(http.MethodPost, "/api/ebpf/reset", nil)
	reqReset.Header.Set("Authorization", "Bearer admin-secret-token")
	wReset := httptest.NewRecorder()

	handler.handleEBPFReset(wReset, reqReset)
	if wReset.Code != http.StatusOK {
		t.Fatalf("Expected 200 for reset, got %d", wReset.Code)
	}

	if len(engine.Flows(ebpf.FlowFilter{})) != 0 {
		t.Errorf("Expected 0 flows after reset, got %d", len(engine.Flows(ebpf.FlowFilter{})))
	}
}
