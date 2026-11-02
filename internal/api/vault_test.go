package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/security"
	"github.com/kLauncher1/dock-radar/internal/vault"
)

func setupTestVaultAPI(t *testing.T) (*HandlerConfig, *security.TokenAuth) {
	auditLogger := audit.NewLogger(100)
	engine, err := vault.NewEngine(vault.DefaultVaultConfig(), auditLogger, nil, "node-api-test")
	if err != nil {
		t.Fatalf("failed to init vault engine: %v", err)
	}

	auth := security.NewTokenAuth("admin-test-token", "viewer-test-token", true)
	cfg := &HandlerConfig{
		VaultEngine: engine,
		AuditLogger: auditLogger,
		TokenAuth:   auth,
		AllowRemote: true,
	}
	return cfg, auth
}

func TestHandleVaultStatus_ViewerAccess(t *testing.T) {
	cfg, _ := setupTestVaultAPI(t)

	// Unauthorized request
	req := httptest.NewRequest(http.MethodGet, "/api/vault/status", nil)
	rr := httptest.NewRecorder()
	cfg.handleVaultStatus(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rr.Code)
	}

	// Viewer request
	req = httptest.NewRequest(http.MethodGet, "/api/vault/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-test-token")
	rr = httptest.NewRecorder()
	cfg.handleVaultStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	var status vault.VaultStatus
	if err := json.NewDecoder(rr.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode status: %v", err)
	}
	if !status.Enabled || status.ActiveKeyID == "" {
		t.Fatalf("unexpected vault status: %+v", status)
	}
}

func TestHandleVaultSecrets_CRUDAndRBAC(t *testing.T) {
	cfg, _ := setupTestVaultAPI(t)

	// 1. Viewer cannot store secret (Forbidden)
	body, _ := json.Marshal(storeSecretRequest{
		Key:   "PROD_DB_URL",
		Type:  vault.SecretTypeEnvVar,
		Value: "postgres://admin:pass@db:5432/main",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/vault/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer viewer-test-token")
	rr := httptest.NewRecorder()
	cfg.handleVaultSecrets(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer storing secret, got %d", rr.Code)
	}

	// 2. Admin stores secret successfully
	req = httptest.NewRequest(http.MethodPost, "/api/vault/secrets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-test-token")
	rr = httptest.NewRecorder()
	cfg.handleVaultSecrets(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rr.Code, rr.Body.String())
	}
	var sum vault.SecretSummary
	json.NewDecoder(rr.Body).Decode(&sum)
	if sum.Key != "PROD_DB_URL" {
		t.Fatalf("expected key PROD_DB_URL, got %s", sum.Key)
	}

	// 3. Viewer lists secrets (metadata only)
	req = httptest.NewRequest(http.MethodGet, "/api/vault/secrets", nil)
	req.Header.Set("Authorization", "Bearer viewer-test-token")
	rr = httptest.NewRecorder()
	cfg.handleVaultSecrets(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	// 4. Admin reads secret with lease
	req = httptest.NewRequest(http.MethodGet, "/api/vault/secrets/read?key=PROD_DB_URL&lease=true&ttl=300", nil)
	req.Header.Set("Authorization", "Bearer admin-test-token")
	rr = httptest.NewRecorder()
	cfg.handleVaultReadSecret(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK reading secret, got %d: %s", rr.Code, rr.Body.String())
	}
	var readResp readSecretResponse
	json.NewDecoder(rr.Body).Decode(&readResp)
	if readResp.Value != "postgres://admin:pass@db:5432/main" {
		t.Fatalf("unexpected decrypted secret value: %s", readResp.Value)
	}
	if readResp.Lease == nil || readResp.Lease.LeaseID == "" {
		t.Fatalf("expected lease to be attached to read response")
	}

	// 5. Admin deletes secret
	req = httptest.NewRequest(http.MethodDelete, "/api/vault/secrets?id="+sum.ID, nil)
	req.Header.Set("Authorization", "Bearer admin-test-token")
	rr = httptest.NewRecorder()
	cfg.handleVaultSecrets(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK deleting secret, got %d", rr.Code)
	}
}

func TestHandleVaultRotate_AdminOnly(t *testing.T) {
	cfg, _ := setupTestVaultAPI(t)

	// Viewer rejected
	req := httptest.NewRequest(http.MethodPost, "/api/vault/rotate", nil)
	req.Header.Set("Authorization", "Bearer viewer-test-token")
	rr := httptest.NewRecorder()
	cfg.handleVaultRotate(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer rotating key, got %d", rr.Code)
	}

	// Admin rotates
	req = httptest.NewRequest(http.MethodPost, "/api/vault/rotate", nil)
	req.Header.Set("Authorization", "Bearer admin-test-token")
	rr = httptest.NewRecorder()
	cfg.handleVaultRotate(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleVaultLeases_LifecycleAndRBAC(t *testing.T) {
	cfg, _ := setupTestVaultAPI(t)

	// Create a secret and acquire lease
	cfg.VaultEngine.StoreSecret("TOKEN_A", vault.SecretTypeToken, []byte("tok-val"), 0, nil, nil, "admin", "127.0.0.1")
	lease, err := cfg.VaultEngine.AcquireLease("TOKEN_A", 10*time.Minute, "admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to acquire lease: %v", err)
	}

	// 1. Viewer lists leases
	req := httptest.NewRequest(http.MethodGet, "/api/vault/leases", nil)
	req.Header.Set("Authorization", "Bearer viewer-test-token")
	rr := httptest.NewRecorder()
	cfg.handleVaultLeases(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK listing leases, got %d", rr.Code)
	}

	// 2. Admin renews lease
	renewBody, _ := json.Marshal(renewLeaseRequest{
		LeaseID:       lease.LeaseID,
		ExtendSeconds: 600,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/vault/leases/renew", bytes.NewReader(renewBody))
	req.Header.Set("Authorization", "Bearer admin-test-token")
	rr = httptest.NewRecorder()
	cfg.handleVaultLeaseRenew(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK renewing lease, got %d: %s", rr.Code, rr.Body.String())
	}

	// 3. Admin revokes lease
	revokeBody, _ := json.Marshal(revokeLeaseRequest{
		LeaseID: lease.LeaseID,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/vault/leases/revoke", bytes.NewReader(revokeBody))
	req.Header.Set("Authorization", "Bearer admin-test-token")
	rr = httptest.NewRecorder()
	cfg.handleVaultLeaseRevoke(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK revoking lease, got %d", rr.Code)
	}
}

func TestHandleVaultTokens_CRUDAndRBAC(t *testing.T) {
	cfg, _ := setupTestVaultAPI(t)

	// Admin creates join token
	tokBody, _ := json.Marshal(createJoinTokenRequest{
		Role:       "worker",
		TTLSeconds: 1800,
		MaxUses:    2,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/vault/tokens", bytes.NewReader(tokBody))
	req.Header.Set("Authorization", "Bearer admin-test-token")
	rr := httptest.NewRecorder()
	cfg.handleVaultTokens(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for join token, got %d: %s", rr.Code, rr.Body.String())
	}

	var tokResp createJoinTokenResponse
	json.NewDecoder(rr.Body).Decode(&tokResp)
	if tokResp.Token == "" || tokResp.TokenID == "" {
		t.Fatalf("unexpected token response: %+v", tokResp)
	}

	// Viewer lists tokens
	req = httptest.NewRequest(http.MethodGet, "/api/vault/tokens", nil)
	req.Header.Set("Authorization", "Bearer viewer-test-token")
	rr = httptest.NewRecorder()
	cfg.handleVaultTokens(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK listing tokens, got %d", rr.Code)
	}

	// Admin revokes token
	req = httptest.NewRequest(http.MethodDelete, "/api/vault/tokens?id="+tokResp.TokenID, nil)
	req.Header.Set("Authorization", "Bearer admin-test-token")
	rr = httptest.NewRecorder()
	cfg.handleVaultTokens(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK revoking token, got %d", rr.Code)
	}
}

func TestHandleVaultConfig_GetAndPost(t *testing.T) {
	cfg, _ := setupTestVaultAPI(t)

	// Viewer reads config
	req := httptest.NewRequest(http.MethodGet, "/api/vault/config", nil)
	req.Header.Set("Authorization", "Bearer viewer-test-token")
	rr := httptest.NewRecorder()
	cfg.handleVaultConfig(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK getting config, got %d", rr.Code)
	}

	// Admin updates config
	newCfg := vault.DefaultVaultConfig()
	newCfg.MaxSecrets = 500
	cBody, _ := json.Marshal(newCfg)
	req = httptest.NewRequest(http.MethodPost, "/api/vault/config", bytes.NewReader(cBody))
	req.Header.Set("Authorization", "Bearer admin-test-token")
	rr = httptest.NewRecorder()
	cfg.handleVaultConfig(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK posting config, got %d", rr.Code)
	}
}
