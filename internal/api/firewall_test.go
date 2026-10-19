package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/firewall"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestFirewallConfig(t *testing.T) (*HandlerConfig, *http.ServeMux) {
	mux := http.NewServeMux()
	tokenAuth := security.NewTokenAuth("admin-secret-token", "viewer-secret-token", false)
	cfg := RegisterRoutesWithSecurity(mux, nil, nil, tokenAuth, false)
	auditLogger := audit.NewLogger(50)
	cfg.FirewallEngine = firewall.NewEngine(firewall.DefaultFirewallConfig(), nil, nil, auditLogger)
	return cfg, mux
}

func TestHandleFirewallStatus(t *testing.T) {
	_, mux := setupTestFirewallConfig(t)

	// Unauthorized request
	req := httptest.NewRequest(http.MethodGet, "/api/firewall/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", w.Code)
	}

	// Viewer request
	req = httptest.NewRequest(http.MethodGet, "/api/firewall/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp FirewallStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode status response: %v", err)
	}
	if !resp.Status.Enabled {
		t.Fatalf("expected firewall status enabled=true")
	}
}

func TestHandleFirewallRules_CRUD(t *testing.T) {
	_, mux := setupTestFirewallConfig(t)

	// 1. Viewer list rules
	req := httptest.NewRequest(http.MethodGet, "/api/firewall/rules", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var listResp FirewallRulesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to decode rules response: %v", err)
	}
	if listResp.TotalCount < 3 {
		t.Fatalf("expected at least 3 default rules, got %d", listResp.TotalCount)
	}

	// 2. Viewer attempt to create rule (should fail 403 Forbidden)
	newRule := firewall.FirewallRule{
		ID:         "fw-api-test",
		Name:       "API Test Rule",
		Priority:   50,
		Enabled:    true,
		Direction:  firewall.DirectionIngress,
		Action:     firewall.ActionDrop,
		Protocol:   firewall.ProtocolTCP,
		DestPort:   "9999",
	}
	payloadBytes, _ := json.Marshal(newRule)
	req = httptest.NewRequest(http.MethodPost, "/api/firewall/rules", bytes.NewReader(payloadBytes))
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer rule creation, got %d", w.Code)
	}

	// 3. Admin create rule (should succeed 200 OK)
	req = httptest.NewRequest(http.MethodPost, "/api/firewall/rules", bytes.NewReader(payloadBytes))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin rule creation, got %d", w.Code)
	}

	// 4. Admin delete rule
	req = httptest.NewRequest(http.MethodDelete, "/api/firewall/rules?id=fw-api-test", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for rule deletion, got %d", w.Code)
	}
}

func TestHandleFirewallIsolation_Lifecycle(t *testing.T) {
	_, mux := setupTestFirewallConfig(t)

	// 1. Admin isolate container
	isolateReq := IsolateContainerRequest{
		ContainerID:    "c-victim",
		ContainerName:  "victim-container",
		IsolationLevel: firewall.IsolationStrictZero,
		Reason:         "Compromised host activity",
		AllowedPeers:   []string{"c-safe"},
		EgressLimitBPS: 1000000,
	}
	payloadBytes, _ := json.Marshal(isolateReq)
	req := httptest.NewRequest(http.MethodPost, "/api/firewall/isolate", bytes.NewReader(payloadBytes))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for isolate, got %d", w.Code)
	}

	// 2. Viewer check isolation list
	req = httptest.NewRequest(http.MethodGet, "/api/firewall/isolation", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var isoResp FirewallIsolationResponse
	_ = json.Unmarshal(w.Body.Bytes(), &isoResp)
	if isoResp.TotalCount != 1 || isoResp.Isolations[0].ContainerID != "c-victim" {
		t.Fatalf("unexpected isolation records: %+v", isoResp)
	}

	// 3. Admin unisolate container
	unisolateReq := UnisolateContainerRequest{ContainerID: "c-victim"}
	uniBytes, _ := json.Marshal(unisolateReq)
	req = httptest.NewRequest(http.MethodPost, "/api/firewall/unisolate", bytes.NewReader(uniBytes))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for unisolate, got %d", w.Code)
	}
}

func TestHandleFirewallSimulate(t *testing.T) {
	_, mux := setupTestFirewallConfig(t)

	simPacket := firewall.PacketPayload{
		SourceIP:      "127.0.0.1",
		DestIP:        "127.0.0.1",
		DestPort:      80,
		Protocol:      firewall.ProtocolTCP,
		Direction:     firewall.DirectionIngress,
		PayloadLength: 64,
	}
	payloadBytes, _ := json.Marshal(simPacket)
	req := httptest.NewRequest(http.MethodPost, "/api/firewall/simulate", bytes.NewReader(payloadBytes))
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var eval firewall.EvaluationResult
	if err := json.Unmarshal(w.Body.Bytes(), &eval); err != nil {
		t.Fatalf("failed to decode eval response: %v", err)
	}
	if eval.Action != firewall.ActionAllow {
		t.Fatalf("expected loopback simulation to ALLOW, got %s", eval.Action)
	}
}

func TestHandleFirewallConfig_GetAndPost(t *testing.T) {
	_, mux := setupTestFirewallConfig(t)

	// GET config
	req := httptest.NewRequest(http.MethodGet, "/api/firewall/config", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var cfg firewall.FirewallConfig
	_ = json.Unmarshal(w.Body.Bytes(), &cfg)
	if !cfg.Enabled {
		t.Fatalf("expected config.Enabled=true")
	}

	// POST update config as Admin
	cfg.ZeroTrustEnabled = true
	cfg.DDoSThresholdPPS = 75000
	cfgBytes, _ := json.Marshal(cfg)
	req = httptest.NewRequest(http.MethodPost, "/api/firewall/config", bytes.NewReader(cfgBytes))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for config update, got %d", w.Code)
	}

	if !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("expected success true in response: %s", w.Body.String())
	}
}
