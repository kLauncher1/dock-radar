package ratelimit

import (
	"testing"
	"time"
)

func TestMeshSync_SignatureAndVerification(t *testing.T) {
	secret := "dock-radar-cluster-key-xyz"
	nodeID := "node-us-east-1"
	bans := []*IPBanRecord{
		{
			IP:         "198.51.100.77",
			Reason:     "DDoS flood",
			OriginNode: nodeID,
			ExpiresAt:  time.Now().Add(10 * time.Minute),
		},
	}

	payload, err := BuildSyncPayload(nodeID, secret, bans)
	if err != nil {
		t.Fatalf("failed to build payload: %v", err)
	}

	if payload.Signature == "" {
		t.Fatalf("expected non-empty signature when secret is provided")
	}

	// Verify valid signature
	err = VerifySignature(secret, payload, 60)
	if err != nil {
		t.Fatalf("expected valid signature verification, got: %v", err)
	}

	// Verify tampering detection
	payload.NodeID = "node-impostor"
	err = VerifySignature(secret, payload, 60)
	if err == nil {
		t.Fatalf("expected signature verification failure after tampering")
	}
}

func TestMeshSync_ReplayAttackDefense(t *testing.T) {
	secret := "secret-key"
	nodeID := "node-1"
	payload, _ := BuildSyncPayload(nodeID, secret, nil)

	// Simulate old timestamp (older than 60s)
	payload.Timestamp = time.Now().Add(-5 * time.Minute).Unix()
	payload.Signature = ComputeSignature(secret, payload.NodeID, payload.Timestamp, payload.ActiveBans)

	err := VerifySignature(secret, payload, 60)
	if err == nil {
		t.Fatalf("expected rejection due to timestamp skew (replay defense)")
	}
}

func TestMeshSync_IngestPeerBans(t *testing.T) {
	store := NewIPBanStore(5, 15*time.Minute, true)
	now := time.Now()

	bans := []IPBanRecord{
		{
			IP:         "203.0.113.11",
			Reason:     "peer-propagated ban",
			OriginNode: "node-2",
			ExpiresAt:  now.Add(5 * time.Minute),
		},
		{
			IP:         "203.0.113.22",
			Reason:     "expired ban",
			OriginNode: "node-2",
			ExpiresAt:  now.Add(-1 * time.Minute), // expired
		},
	}

	applied := IngestPeerBans(store, bans)
	if applied != 1 {
		t.Fatalf("expected 1 ban applied, got %d", applied)
	}

	banned, record := store.IsBanned("203.0.113.11")
	if !banned || record == nil {
		t.Fatalf("expected IP to be banned after peer ingestion")
	}
	if record.OriginNode != "node-2" {
		t.Fatalf("expected origin node node-2, got %s", record.OriginNode)
	}
}
