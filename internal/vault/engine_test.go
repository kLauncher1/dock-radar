package vault

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
)

func setupTestEngine(t *testing.T) *Engine {
	auditLogger := audit.NewLogger(100)
	cfg := DefaultVaultConfig()
	cfg.RotationInterval = 1 * time.Hour
	engine, err := NewEngine(cfg, auditLogger, nil, "test-node-01")
	if err != nil {
		t.Fatalf("failed to create test engine: %v", err)
	}
	return engine
}

func TestEngine_StoreAndReadSecret(t *testing.T) {
	engine := setupTestEngine(t)

	plaintext := []byte("mongodb+srv://admin:secret99@cluster0.net")
	summary, err := engine.StoreSecret("MONGO_URI", SecretTypeEnvVar, plaintext, 2*time.Hour, map[string]string{"env": "prod"}, nil, "admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to store secret: %v", err)
	}

	if summary.Key != "MONGO_URI" || summary.Version != 1 || summary.Type != SecretTypeEnvVar {
		t.Fatalf("unexpected secret summary: %+v", summary)
	}

	// Read without lease
	lease, decPlaintext, err := engine.ReadSecret("MONGO_URI", false, 0, "admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to read secret: %v", err)
	}
	if lease != nil {
		t.Fatalf("expected nil lease when issueLease is false")
	}
	if string(decPlaintext) != "mongodb+srv://admin:secret99@cluster0.net" {
		t.Fatalf("unexpected plaintext: %s", string(decPlaintext))
	}

	// Read with lease
	lease, _, err = engine.ReadSecret("MONGO_URI", true, 30*time.Minute, "service-auth", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to read secret with lease: %v", err)
	}
	if lease == nil || lease.LeaseID == "" {
		t.Fatalf("expected active lease to be issued")
	}

	// Read by Secret ID
	_, decByID, err := engine.ReadSecret(summary.ID, false, 0, "admin", "127.0.0.1")
	if err != nil || string(decByID) != "mongodb+srv://admin:secret99@cluster0.net" {
		t.Fatalf("failed to read secret by ID: %v", err)
	}
}

func TestEngine_UpdateSecret(t *testing.T) {
	engine := setupTestEngine(t)

	engine.StoreSecret("API_TOKEN", SecretTypeToken, []byte("v1-token"), 0, nil, nil, "admin", "127.0.0.1")
	sum2, err := engine.StoreSecret("API_TOKEN", SecretTypeToken, []byte("v2-token"), 0, nil, nil, "admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to update secret: %v", err)
	}

	if sum2.Version != 2 {
		t.Fatalf("expected version 2 after update, got %d", sum2.Version)
	}

	_, dec, _ := engine.ReadSecret("API_TOKEN", false, 0, "admin", "127.0.0.1")
	if string(dec) != "v2-token" {
		t.Fatalf("expected updated value 'v2-token', got %s", string(dec))
	}
}

func TestEngine_DeleteSecret(t *testing.T) {
	engine := setupTestEngine(t)

	sum, _ := engine.StoreSecret("TEMP_SECRET", SecretTypeGeneric, []byte("temporary"), 0, nil, nil, "admin", "127.0.0.1")
	if err := engine.DeleteSecret(sum.ID, "admin", "127.0.0.1"); err != nil {
		t.Fatalf("failed to delete secret: %v", err)
	}

	_, _, err := engine.ReadSecret("TEMP_SECRET", false, 0, "admin", "127.0.0.1")
	if err == nil {
		t.Fatalf("expected error reading shredded secret, got nil")
	}
}

func TestEngine_RotateMasterKey(t *testing.T) {
	engine := setupTestEngine(t)

	// Store secret with key 1
	sum, _ := engine.StoreSecret("JWT_SECRET", SecretTypeToken, []byte("jwt-signing-key-1234"), 0, nil, nil, "admin", "127.0.0.1")
	oldKeyID := sum.KeyID

	// Rotate master key
	newEntry, err := engine.RotateMasterKey("admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to rotate master key: %v", err)
	}
	if newEntry.KeyID == oldKeyID {
		t.Fatalf("expected new key ID to differ from old key ID")
	}

	// Secret should still decrypt transparently using the new key
	_, dec, err := engine.ReadSecret("JWT_SECRET", false, 0, "admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to decrypt secret after key rotation: %v", err)
	}
	if !bytes.Equal(dec, []byte("jwt-signing-key-1234")) {
		t.Fatalf("decrypted value mismatch after rotation")
	}

	// Verify secret has been re-encrypted with new key ID
	secrets := engine.ListSecrets("")
	if len(secrets) != 1 || secrets[0].KeyID != newEntry.KeyID {
		t.Fatalf("expected secret to reference new key ID %s, got %s", newEntry.KeyID, secrets[0].KeyID)
	}
}

func TestEngine_JoinTokensAndLeases(t *testing.T) {
	engine := setupTestEngine(t)

	// Join token
	plain, tok, err := engine.CreateJoinToken("worker", 2*time.Hour, 3, "admin", "127.0.0.1")
	if err != nil || plain == "" || tok.TokenID == "" {
		t.Fatalf("failed to create join token: %v", err)
	}

	tokens := engine.ListJoinTokens()
	if len(tokens) != 1 {
		t.Fatalf("expected 1 join token, got %d", len(tokens))
	}

	if err := engine.RevokeJoinToken(tok.TokenID, "admin", "127.0.0.1"); err != nil {
		t.Fatalf("failed to revoke join token: %v", err)
	}

	// Leases
	sum, _ := engine.StoreSecret("CACHE_KEY", SecretTypeGeneric, []byte("redis-key"), 0, nil, nil, "admin", "127.0.0.1")
	lease, err := engine.AcquireLease(sum.ID, 30*time.Minute, "app", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to acquire lease: %v", err)
	}

	renewed, err := engine.RenewLease(lease.LeaseID, 15*time.Minute, "app", "127.0.0.1")
	if err != nil || !renewed.ExpiresAt.After(lease.ExpiresAt) {
		t.Fatalf("failed to renew lease: %v", err)
	}

	_, err = engine.RevokeLease(lease.LeaseID, "app", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to revoke lease: %v", err)
	}
}

func TestEngine_ReplicationSync(t *testing.T) {
	engine1 := setupTestEngine(t)
	engine2 := setupTestEngine(t)

	engine1.StoreSecret("SHARED_CFG", SecretTypeEnvVar, []byte("replica-value"), 0, nil, nil, "admin", "127.0.0.1")

	payload, err := engine1.ExportSyncPayload()
	if err != nil {
		t.Fatalf("failed to export sync payload: %v", err)
	}

	// Share keyring active key so engine2 can ingest
	engine2.cfg.ReplicationSecret = engine1.cfg.ReplicationSecret
	engine2.keyring[engine1.activeKeyID] = engine1.keyring[engine1.activeKeyID]

	ingested, err := engine2.IngestSyncPayload(payload, "peer-sync", "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to ingest sync payload: %v", err)
	}
	if ingested != 1 {
		t.Fatalf("expected 1 secret ingested, got %d", ingested)
	}

	_, dec, err := engine2.ReadSecret("SHARED_CFG", false, 0, "admin", "127.0.0.1")
	if err != nil || string(dec) != "replica-value" {
		t.Fatalf("failed to decrypt ingested replicated secret: %v", err)
	}
}

func TestEngine_LifecycleAndStatus(t *testing.T) {
	engine := setupTestEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx)
	defer engine.Stop()

	status := engine.Status()
	if !status.Enabled || status.ActiveKeyID == "" {
		t.Fatalf("unexpected vault status: %+v", status)
	}

	cfg := engine.Config()
	cfg.MaxSecrets = 2000
	if err := engine.UpdateConfig(cfg, "admin", "127.0.0.1"); err != nil {
		t.Fatalf("failed to update vault config: %v", err)
	}
	if engine.Config().MaxSecrets != 2000 {
		t.Fatalf("config update did not take effect")
	}
}
