package vault

import (
	"errors"
	"testing"
	"time"
)

func TestJoinTokenManager_Lifecycle(t *testing.T) {
	jm := NewJoinTokenManager()

	// 1. Create single-use token
	plainToken, meta, err := jm.CreateToken("admin", 1*time.Hour, 1, "admin-user")
	if err != nil {
		t.Fatalf("failed to create join token: %v", err)
	}
	if plainToken == "" || meta.TokenID == "" {
		t.Fatalf("unexpected token output: %s, %+v", plainToken, meta)
	}

	// 2. Consume token successfully
	consumed, err := jm.ValidateAndConsume(plainToken, "admin")
	if err != nil {
		t.Fatalf("failed to consume valid join token: %v", err)
	}
	if consumed.UsesCount != 1 {
		t.Fatalf("expected UsesCount 1, got %d", consumed.UsesCount)
	}

	// 3. Second consume fails because max_uses was 1
	_, err = jm.ValidateAndConsume(plainToken, "admin")
	if err == nil || !errors.Is(err, ErrJoinTokenExhausted) {
		t.Fatalf("expected ErrJoinTokenExhausted on exhausted token, got: %v", err)
	}

	// 4. Create multi-use token and test revocation
	plainMulti, multiMeta, _ := jm.CreateToken("viewer", 1*time.Hour, 5, "admin-user")
	if err := jm.RevokeToken(multiMeta.TokenID); err != nil {
		t.Fatalf("failed to revoke token: %v", err)
	}

	_, err = jm.ValidateAndConsume(plainMulti, "viewer")
	if err == nil || !errors.Is(err, ErrJoinTokenInvalid) {
		t.Fatalf("expected ErrJoinTokenInvalid on revoked token, got: %v", err)
	}
}

func TestJoinTokenManager_RoleMismatch(t *testing.T) {
	jm := NewJoinTokenManager()
	plainToken, _, _ := jm.CreateToken("viewer", 1*time.Hour, 2, "admin-user")

	_, err := jm.ValidateAndConsume(plainToken, "admin")
	if err == nil {
		t.Fatalf("expected error on role mismatch, got nil")
	}
}

func TestReplicationManager_SyncPayload(t *testing.T) {
	rm := NewReplicationManager()
	key := []byte("cluster-shared-secret-key-32bytes")

	dummySecrets := []VaultSecret{
		{
			ID:         "sec_01",
			Key:        "DATABASE_URL",
			Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0",
			Nonce:      "0123456789abcdef01234567",
			KeyID:      "key_01",
			Version:    1,
			CreatedAt:  time.Now().UTC(),
		},
	}

	payload, err := rm.BuildSyncPayload("node-1", "cluster-east", 1, dummySecrets, key)
	if err != nil {
		t.Fatalf("failed to build sync payload: %v", err)
	}
	if payload.Signature == "" {
		t.Fatalf("expected payload signature to be populated")
	}

	// Ingest valid payload
	ingested, err := rm.VerifyAndIngest(payload, key, 60*time.Second)
	if err != nil {
		t.Fatalf("failed to verify and ingest payload: %v", err)
	}
	if len(ingested) != 1 || ingested[0].Key != "DATABASE_URL" {
		t.Fatalf("unexpected ingested secrets: %+v", ingested)
	}

	// Tampered secret in payload
	payload.Secrets[0].Key = "MALICIOUS_KEY"
	_, err = rm.VerifyAndIngest(payload, key, 60*time.Second)
	if err == nil {
		t.Fatalf("expected verification failure on tampered payload")
	}
}

func TestReplicationManager_TimestampDrift(t *testing.T) {
	rm := NewReplicationManager()
	key := []byte("cluster-shared-secret-key-32bytes")

	payload, _ := rm.BuildSyncPayload("node-1", "cluster-east", 1, nil, key)
	// Simulate 100 seconds in past
	payload.Timestamp -= 100

	// Recompute signature for altered timestamp
	canonical, _ := serializePayloadCanonical(payload)
	payload.Signature = ComputeHMACSHA256(key, canonical)

	// Drift check with 30s limit
	_, err := rm.VerifyAndIngest(payload, key, 30*time.Second)
	if err == nil || !errors.Is(err, ErrReplicationRejected) {
		t.Fatalf("expected ErrReplicationRejected for drifted timestamp, got: %v", err)
	}
}
