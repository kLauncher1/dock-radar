package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/acme"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestACMEHandler(t *testing.T) (*HandlerConfig, *http.ServeMux) {
	mux := http.NewServeMux()
	auditLogger := audit.NewLogger(50)
	cfg := acme.DefaultACMEConfig()
	engine, err := acme.NewEngine(cfg, auditLogger, nil)
	if err != nil {
		t.Fatalf("failed to create test acme engine: %v", err)
	}

	tokenAuth := security.NewTokenAuth("admin-secret-token", "viewer-secret-token", true)
	handlerCfg := &HandlerConfig{
		ACMEEngine:  engine,
		AuditLogger: auditLogger,
		TokenAuth:   tokenAuth,
		AllowRemote: true,
	}

	mux.HandleFunc("/api/acme/status", handlerCfg.handleACMEStatus)
	mux.HandleFunc("/api/acme/certificates", handlerCfg.handleACMECertificates)
	mux.HandleFunc("/api/acme/certificates/detail", handlerCfg.handleACMECertificateDetail)
	mux.HandleFunc("/api/acme/order", handlerCfg.handleACMEOrder)
	mux.HandleFunc("/api/acme/renew", handlerCfg.handleACMERenew)
	mux.HandleFunc("/api/acme/revoke", handlerCfg.handleACMERevoke)
	mux.HandleFunc("/api/acme/challenges", handlerCfg.handleACMEChallenges)
	mux.HandleFunc("/api/acme/challenges/dns", handlerCfg.handleACMEDNSChallengeComplete)
	mux.HandleFunc("/api/acme/config", handlerCfg.handleACMEConfig)
	mux.HandleFunc("/.well-known/acme-challenge/", handlerCfg.handleACMEHTTP01Challenge)

	return handlerCfg, mux
}

func TestHandleACMEStatus_ViewerAccess(t *testing.T) {
	_, mux := setupTestACMEHandler(t)

	// Without token
	req := httptest.NewRequest(http.MethodGet, "/api/acme/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rec.Code)
	}

	// With viewer token
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/acme/status", nil)
	reqAuth.Header.Set("Authorization", "Bearer viewer-secret-token")
	recAuth := httptest.NewRecorder()
	mux.ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 with viewer token, got %d", recAuth.Code)
	}

	var status acme.ACMEStatus
	if err := json.NewDecoder(recAuth.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode status: %v", err)
	}
	if !status.Enabled {
		t.Fatalf("expected Enabled=true")
	}
}

func TestHandleACMEOrder_AndCertificates(t *testing.T) {
	_, mux := setupTestACMEHandler(t)

	// 1. Order new certificate (Viewer should fail with 403 Forbidden)
	orderReq := IssueCertRequest{
		Domain:        "service.internal.net",
		SANs:          []string{"api.service.internal.net"},
		Provider:      acme.ProviderLetsEncryptStaging,
		ChallengeType: acme.ChallengeHTTP01,
	}
	bodyBytes, _ := json.Marshal(orderReq)

	reqViewer := httptest.NewRequest(http.MethodPost, "/api/acme/order", bytes.NewReader(bodyBytes))
	reqViewer.Header.Set("Authorization", "Bearer viewer-secret-token")
	recViewer := httptest.NewRecorder()
	mux.ServeHTTP(recViewer, reqViewer)
	if recViewer.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer ordering certificate, got %d", recViewer.Code)
	}

	// 2. Order new certificate with Admin token (Should succeed 201 Created)
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/acme/order", bytes.NewReader(bodyBytes))
	reqAdmin.Header.Set("Authorization", "Bearer admin-secret-token")
	recAdmin := httptest.NewRecorder()
	mux.ServeHTTP(recAdmin, reqAdmin)
	if recAdmin.Code != http.StatusCreated {
		t.Fatalf("expected 201 for admin ordering cert, got %d: %s", recAdmin.Code, recAdmin.Body.String())
	}

	var issued acme.ManagedCert
	_ = json.NewDecoder(recAdmin.Body).Decode(&issued)
	if issued.Domain != "service.internal.net" {
		t.Fatalf("expected domain service.internal.net, got %s", issued.Domain)
	}

	// 3. List certificates
	reqList := httptest.NewRequest(http.MethodGet, "/api/acme/certificates", nil)
	reqList.Header.Set("Authorization", "Bearer viewer-secret-token")
	recList := httptest.NewRecorder()
	mux.ServeHTTP(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Fatalf("expected 200 for certificates list, got %d", recList.Code)
	}

	var list []acme.CertSummary
	_ = json.NewDecoder(recList.Body).Decode(&list)
	if len(list) < 1 {
		t.Fatalf("expected at least 1 certificate in list, got %d", len(list))
	}

	// 4. Get certificate detail
	reqDetail := httptest.NewRequest(http.MethodGet, "/api/acme/certificates/detail?domain=service.internal.net", nil)
	reqDetail.Header.Set("Authorization", "Bearer viewer-secret-token")
	recDetail := httptest.NewRecorder()
	mux.ServeHTTP(recDetail, reqDetail)
	if recDetail.Code != http.StatusOK {
		t.Fatalf("expected 200 for certificate detail, got %d", recDetail.Code)
	}

	// 5. Force Renew
	renewBody, _ := json.Marshal(DomainActionRequest{Domain: "service.internal.net"})
	reqRenew := httptest.NewRequest(http.MethodPost, "/api/acme/renew", bytes.NewReader(renewBody))
	reqRenew.Header.Set("Authorization", "Bearer admin-secret-token")
	recRenew := httptest.NewRecorder()
	mux.ServeHTTP(recRenew, reqRenew)
	if recRenew.Code != http.StatusOK {
		t.Fatalf("expected 200 for renew, got %d: %s", recRenew.Code, recRenew.Body.String())
	}

	// 6. Revoke
	revokeBody, _ := json.Marshal(DomainActionRequest{Domain: "service.internal.net"})
	reqRevoke := httptest.NewRequest(http.MethodPost, "/api/acme/revoke", bytes.NewReader(revokeBody))
	reqRevoke.Header.Set("Authorization", "Bearer admin-secret-token")
	recRevoke := httptest.NewRecorder()
	mux.ServeHTTP(recRevoke, reqRevoke)
	if recRevoke.Code != http.StatusOK {
		t.Fatalf("expected 200 for revoke, got %d: %s", recRevoke.Code, recRevoke.Body.String())
	}
}

func TestHandleACMEHTTP01ChallengeResponder(t *testing.T) {
	handlerCfg, mux := setupTestACMEHandler(t)

	// Register a challenge token in the engine
	handlerCfg.ACMEEngine.RegisterChallenge(&acme.ChallengeRecord{
		Token:            "test-http-token-999",
		KeyAuthorization: "test-http-token-999.thumbprint-abc-123",
		Domain:           "test.example.com",
		Type:             acme.ChallengeHTTP01,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(1 * time.Hour),
	})

	// Public request without any Authorization header
	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/test-http-token-999", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid HTTP-01 challenge token, got %d", rec.Code)
	}
	if rec.Body.String() != "test-http-token-999.thumbprint-abc-123" {
		t.Fatalf("unexpected challenge response payload: %q", rec.Body.String())
	}

	// Non-existent token -> 404
	reqUnknown := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/non-existent-token", nil)
	recUnknown := httptest.NewRecorder()
	mux.ServeHTTP(recUnknown, reqUnknown)
	if recUnknown.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown token, got %d", recUnknown.Code)
	}
}

func TestHandleACMEConfig_GetAndPost(t *testing.T) {
	_, mux := setupTestACMEHandler(t)

	// GET config
	reqGet := httptest.NewRequest(http.MethodGet, "/api/acme/config", nil)
	reqGet.Header.Set("Authorization", "Bearer viewer-secret-token")
	recGet := httptest.NewRecorder()
	mux.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Fatalf("expected 200 for get config, got %d", recGet.Code)
	}

	// POST config update
	newCfg := acme.DefaultACMEConfig()
	newCfg.RenewThresholdDays = 40
	newCfg.Email = "ops@example.com"
	bodyBytes, _ := json.Marshal(newCfg)

	reqPost := httptest.NewRequest(http.MethodPost, "/api/acme/config", bytes.NewReader(bodyBytes))
	reqPost.Header.Set("Authorization", "Bearer admin-secret-token")
	recPost := httptest.NewRecorder()
	mux.ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusOK {
		t.Fatalf("expected 200 for update config, got %d", recPost.Code)
	}
}
