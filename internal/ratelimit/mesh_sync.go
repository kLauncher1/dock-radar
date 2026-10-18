package ratelimit

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// SyncPayload represents the rate limiter state exchanged between cluster mesh nodes.
type SyncPayload struct {
	NodeID      string        `json:"node_id"`
	Timestamp   int64         `json:"timestamp"` // Unix epoch seconds
	ActiveBans  []IPBanRecord `json:"active_bans"`
	TenantUsage []QuotaUsage  `json:"tenant_usage,omitempty"`
	Signature   string        `json:"signature"` // HMAC-SHA256 hex string
}

// ComputeSignature calculates the HMAC-SHA256 signature for a SyncPayload using the shared secret.
func ComputeSignature(secret string, nodeID string, timestamp int64, bans []IPBanRecord) string {
	if secret == "" {
		return ""
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%s:%d:", nodeID, timestamp)))

	// Deterministic serialization of active bans
	for _, b := range bans {
		mac.Write([]byte(fmt.Sprintf("%s:%s:%d|", b.IP, b.OriginNode, b.ExpiresAt.Unix())))
	}

	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature validates payload signature and checks timestamp freshness (anti-replay).
func VerifySignature(secret string, payload *SyncPayload, maxSkewSeconds int64) error {
	if payload == nil {
		return errors.New("sync payload is nil")
	}

	if maxSkewSeconds <= 0 {
		maxSkewSeconds = 60
	}

	// Verify timestamp freshness
	now := time.Now().Unix()
	if int64(math.Abs(float64(now-payload.Timestamp))) > maxSkewSeconds {
		return errors.New("sync payload rejected: timestamp skew exceeds acceptable window")
	}

	// If secret is set, signature must be present and match
	if secret != "" {
		expectedSig := ComputeSignature(secret, payload.NodeID, payload.Timestamp, payload.ActiveBans)
		if subtle.ConstantTimeCompare([]byte(payload.Signature), []byte(expectedSig)) != 1 {
			return errors.New("sync payload signature mismatch: unauthorized cluster peer")
		}
	}

	return nil
}

// IngestPeerBans merges peer-discovered IP bans into the local IPBanStore.
// Returns count of newly applied or updated bans.
func IngestPeerBans(store *IPBanStore, bans []IPBanRecord) int {
	if store == nil || len(bans) == 0 {
		return 0
	}

	now := time.Now()
	applied := 0

	for _, b := range bans {
		if now.After(b.ExpiresAt) {
			continue // Skip already expired bans
		}

		remainingDuration := b.ExpiresAt.Sub(now)
		if remainingDuration <= 0 {
			continue
		}

		_, err := store.Ban(b.IP, b.Reason, remainingDuration, b.OriginNode)
		if err == nil {
			applied++
		}
	}

	return applied
}

// BuildSyncPayload creates an authenticated SyncPayload for broadcast to mesh peers.
func BuildSyncPayload(nodeID string, secret string, bans []*IPBanRecord) (*SyncPayload, error) {
	if nodeID == "" {
		nodeID = "local-node"
	}

	now := time.Now().Unix()
	records := make([]IPBanRecord, 0, len(bans))
	for _, b := range bans {
		if b != nil {
			records = append(records, *b)
		}
	}

	sig := ComputeSignature(secret, nodeID, now, records)

	return &SyncPayload{
		NodeID:     nodeID,
		Timestamp:  now,
		ActiveBans: records,
		Signature:  sig,
	}, nil
}

// SerializeSyncPayload produces a JSON byte slice from SyncPayload.
func SerializeSyncPayload(p *SyncPayload) ([]byte, error) {
	return json.Marshal(p)
}

// DeserializeSyncPayload parses a JSON byte slice into SyncPayload.
func DeserializeSyncPayload(data []byte) (*SyncPayload, error) {
	var p SyncPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to decode sync payload: %w", err)
	}
	return &p, nil
}
