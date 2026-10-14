package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/healing"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestHealingConfig() *HandlerConfig {
	limiter := security.NewRateLimiter(100.0, 100.0)
	auditLogger := audit.NewLogger(100)
	policyStore := healing.NewPolicyStore(healing.DefaultPolicyConfig())
	history := healing.NewHistoryBuffer(100)
	engine := healing.NewRemediationEngine(nil, policyStore, history, auditLogger)

	return &HandlerConfig{
		RateLimiter:   limiter,
		AuditLogger:   auditLogger,
		HealingEngine: engine,
		AllowRemote:   true,
	}
}

func TestHealingConfig_GetAndPost(t *testing.T) {
	cfg := setupTestHealingConfig()

	// 1. GET /api/healing/config
	req := httptest.NewRequest(http.MethodGet, "/api/healing/config", nil)
	rec := httptest.NewRecorder()
	cfg.handleHealingConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from GET /api/healing/config, got %d", rec.Code)
	}

	var policy healing.PolicyConfig
	if err := json.NewDecoder(rec.Body).Decode(&policy); err != nil {
		t.Fatalf("Failed to decode policy config: %v", err)
	}
	if !policy.Enabled || policy.MaxAttempts != 3 {
		t.Errorf("Unexpected default policy values: %+v", policy)
	}

	// 2. POST /api/healing/config (Valid update)
	updated := policy
	updated.MaxAttempts = 5
	updated.BaseBackoffSec = 4
	payloadBytes, _ := json.Marshal(updated)

	postReq := httptest.NewRequest(http.MethodPost, "/api/healing/config", bytes.NewReader(payloadBytes))
	postReq.Header.Set("Content-Type", "application/json")
	postReq.RemoteAddr = "127.0.0.1:50000"
	postRec := httptest.NewRecorder()
	cfg.handleHealingConfig(postRec, postReq)

	if postRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from POST /api/healing/config, got %d: %s", postRec.Code, postRec.Body.String())
	}

	var saved healing.PolicyConfig
	if err := json.NewDecoder(postRec.Body).Decode(&saved); err != nil {
		t.Fatalf("Failed to decode saved policy: %v", err)
	}
	if saved.MaxAttempts != 5 || saved.BaseBackoffSec != 4 {
		t.Errorf("Expected MaxAttempts=5, BaseBackoffSec=4, got %+v", saved)
	}

	// 3. POST /api/healing/config (Invalid bounds)
	invalid := policy
	invalid.MaxAttempts = 999
	badPayload, _ := json.Marshal(invalid)

	badReq := httptest.NewRequest(http.MethodPost, "/api/healing/config", bytes.NewReader(badPayload))
	badReq.Header.Set("Content-Type", "application/json")
	badReq.RemoteAddr = "127.0.0.1:50000"
	badRec := httptest.NewRecorder()
	cfg.handleHealingConfig(badRec, badReq)

	if badRec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request on invalid bounds, got %d", badRec.Code)
	}
}

func TestHealingStatus_Get(t *testing.T) {
	cfg := setupTestHealingConfig()

	req := httptest.NewRequest(http.MethodGet, "/api/healing/status", nil)
	rec := httptest.NewRecorder()
	cfg.handleHealingStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from GET /api/healing/status, got %d", rec.Code)
	}

	var stats healing.HealingStats
	if err := json.NewDecoder(rec.Body).Decode(&stats); err != nil {
		t.Fatalf("Failed to decode healing stats: %v", err)
	}

	if !stats.Enabled {
		t.Errorf("Expected healing stats to be enabled by default")
	}
}

func TestHealingHistory_Get(t *testing.T) {
	cfg := setupTestHealingConfig()
	cfg.HealingEngine.History().Record(healing.RemediationEvent{
		ContainerID:   "c-1",
		ContainerName: "nginx",
		Trigger:       "oom_killed",
		Action:        "restart",
		Status:        "success",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/healing/history?limit=10", nil)
	rec := httptest.NewRecorder()
	cfg.handleHealingHistory(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from GET /api/healing/history, got %d", rec.Code)
	}

	var events []healing.RemediationEvent
	if err := json.NewDecoder(rec.Body).Decode(&events); err != nil {
		t.Fatalf("Failed to decode history events: %v", err)
	}

	if len(events) != 1 || events[0].ContainerID != "c-1" {
		t.Errorf("Expected 1 event for c-1, got %+v", events)
	}
}

func TestHealingReset_Post(t *testing.T) {
	cfg := setupTestHealingConfig()

	// 1. Reset specific container
	req := httptest.NewRequest(http.MethodPost, "/api/healing/reset?id=test-container", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()
	cfg.handleHealingReset(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from POST /api/healing/reset?id=test-container, got %d", rec.Code)
	}

	// 2. Reset all containers
	allReq := httptest.NewRequest(http.MethodPost, "/api/healing/reset", nil)
	allReq.RemoteAddr = "127.0.0.1:50000"
	allRec := httptest.NewRecorder()
	cfg.handleHealingReset(allRec, allReq)

	if allRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from POST /api/healing/reset, got %d", allRec.Code)
	}

	// 3. Reset with invalid container ID
	badReq := httptest.NewRequest(http.MethodPost, "/api/healing/reset?id=bad/path/injection", nil)
	badReq.RemoteAddr = "127.0.0.1:50000"
	badRec := httptest.NewRecorder()
	cfg.handleHealingReset(badRec, badReq)

	if badRec.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request on invalid ID, got %d", badRec.Code)
	}
}

func TestHealingEndpoints_AuthGuard(t *testing.T) {
	tokenAuth := security.NewTokenAuth("admin-secret", "viewer-secret", false)
	limiter := security.NewRateLimiter(100.0, 100.0)
	policyStore := healing.NewPolicyStore(healing.DefaultPolicyConfig())
	history := healing.NewHistoryBuffer(100)
	engine := healing.NewRemediationEngine(nil, policyStore, history, nil)

	cfg := &HandlerConfig{
		RateLimiter:   limiter,
		HealingEngine: engine,
		TokenAuth:     tokenAuth,
		AllowRemote:   true,
	}

	// 1. Viewer token accessing GET /api/healing/config -> Allowed
	reqGet := httptest.NewRequest(http.MethodGet, "/api/healing/config", nil)
	reqGet.Header.Set("Authorization", "Bearer viewer-secret")
	recGet := httptest.NewRecorder()
	cfg.handleHealingConfig(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for viewer on GET, got %d", recGet.Code)
	}

	// 2. Viewer token attempting POST /api/healing/config -> Forbidden (403)
	payload, _ := json.Marshal(healing.DefaultPolicyConfig())
	reqPost := httptest.NewRequest(http.MethodPost, "/api/healing/config", bytes.NewReader(payload))
	reqPost.Header.Set("Authorization", "Bearer viewer-secret")
	recPost := httptest.NewRecorder()
	cfg.handleHealingConfig(recPost, reqPost)

	if recPost.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for viewer on POST, got %d", recPost.Code)
	}

	// 3. Unauthenticated request -> Unauthorized (401)
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/healing/status", nil)
	unauthRec := httptest.NewRecorder()
	cfg.handleHealingStatus(unauthRec, unauthReq)

	if unauthRec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for missing token, got %d", unauthRec.Code)
	}
}
