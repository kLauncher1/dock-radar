package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// JoinTokenManager handles creation, validation, consumption, and revocation of cluster join tokens.
type JoinTokenManager struct {
	mu     sync.RWMutex
	tokens map[string]*ClusterJoinToken // keyed by TokenID
}

// NewJoinTokenManager creates an initialized JoinTokenManager.
func NewJoinTokenManager() *JoinTokenManager {
	return &JoinTokenManager{
		tokens: make(map[string]*ClusterJoinToken),
	}
}

// CreateToken generates a revocable single-use or multi-use cluster join token.
// It returns the plaintext token (for one-time distribution) and the stored token metadata.
func (jm *JoinTokenManager) CreateToken(role string, ttl time.Duration, maxUses int, createdBy string) (string, *ClusterJoinToken, error) {
	if role == "" {
		role = "viewer"
	}
	if maxUses <= 0 {
		maxUses = 1
	}
	if ttl < 1*time.Minute {
		ttl = 1 * time.Hour
	}

	rawBytes, err := GenerateRandomBytes(24)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate token entropy: %w", err)
	}

	plaintextToken := "dkt_" + hex.EncodeToString(rawBytes)
	tokenID := GenerateTokenID()

	hash := sha256.Sum256([]byte(plaintextToken))
	tokenHash := hex.EncodeToString(hash[:])

	now := time.Now().UTC()
	token := &ClusterJoinToken{
		TokenID:   tokenID,
		TokenHash: tokenHash,
		NodeRole:  role,
		ExpiresAt: now.Add(ttl),
		MaxUses:   maxUses,
		UsesCount: 0,
		Revoked:   false,
		CreatedAt: now,
		CreatedBy: createdBy,
	}

	jm.mu.Lock()
	jm.tokens[tokenID] = token
	jm.mu.Unlock()

	return plaintextToken, cloneJoinToken(token), nil
}

// ValidateAndConsume verifies the plaintext token against stored hashes and increments use count.
func (jm *JoinTokenManager) ValidateAndConsume(plaintextToken string, expectedRole string) (*ClusterJoinToken, error) {
	if plaintextToken == "" {
		return nil, ErrJoinTokenInvalid
	}

	hash := sha256.Sum256([]byte(plaintextToken))
	providedHash := hex.EncodeToString(hash[:])

	jm.mu.Lock()
	defer jm.mu.Unlock()

	now := time.Now().UTC()
	for _, tok := range jm.tokens {
		if ConstantTimeCompareString(tok.TokenHash, providedHash) {
			if tok.Revoked {
				return nil, ErrJoinTokenInvalid
			}
			if now.After(tok.ExpiresAt) {
				return nil, ErrJoinTokenInvalid
			}
			if tok.MaxUses > 0 && tok.UsesCount >= tok.MaxUses {
				return nil, ErrJoinTokenExhausted
			}
			if expectedRole != "" && tok.NodeRole != expectedRole {
				return nil, fmt.Errorf("token role mismatch: token grants %s, requires %s", tok.NodeRole, expectedRole)
			}

			tok.UsesCount++
			return cloneJoinToken(tok), nil
		}
	}

	return nil, ErrJoinTokenInvalid
}

// RevokeToken marks a join token as revoked so it can never be used again.
func (jm *JoinTokenManager) RevokeToken(tokenID string) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	tok, exists := jm.tokens[tokenID]
	if !exists {
		return errors.New("join token not found")
	}

	tok.Revoked = true
	return nil
}

// ListTokens returns a snapshot of all active and historical join tokens.
func (jm *JoinTokenManager) ListTokens() []*ClusterJoinToken {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	list := make([]*ClusterJoinToken, 0, len(jm.tokens))
	for _, tok := range jm.tokens {
		list = append(list, cloneJoinToken(tok))
	}
	return list
}

// ReplicationManager handles end-to-end encrypted cluster secret sharing and synchronized replication.
type ReplicationManager struct {
	mu sync.RWMutex
}

// NewReplicationManager creates an initialized ReplicationManager.
func NewReplicationManager() *ReplicationManager {
	return &ReplicationManager{}
}

// BuildSyncPayload prepares an authenticated zero-knowledge replication message containing encrypted secrets.
func (rm *ReplicationManager) BuildSyncPayload(nodeID, clusterID string, term int, secrets []VaultSecret, replicationKey []byte) (*VaultSyncPayload, error) {
	if len(replicationKey) == 0 {
		return nil, errors.New("replication key is required for cluster secret sharing")
	}

	payload := &VaultSyncPayload{
		NodeID:    nodeID,
		ClusterID: clusterID,
		Timestamp: time.Now().UTC().Unix(),
		Term:      term,
		Secrets:   secrets,
	}

	canonicalData, err := serializePayloadCanonical(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize canonical replication payload: %w", err)
	}

	payload.Signature = ComputeHMACSHA256(replicationKey, canonicalData)
	return payload, nil
}

// VerifyAndIngest validates HMAC signature, checks timestamp replay windows, and returns verified secrets.
func (rm *ReplicationManager) VerifyAndIngest(payload *VaultSyncPayload, replicationKey []byte, maxDrift time.Duration) ([]VaultSecret, error) {
	if payload == nil {
		return nil, errors.New("empty sync payload")
	}
	if len(replicationKey) == 0 {
		return nil, errors.New("replication key required for verification")
	}

	now := time.Now().UTC().Unix()
	drift := now - payload.Timestamp
	if drift < 0 {
		drift = -drift
	}
	if time.Duration(drift)*time.Second > maxDrift {
		return nil, fmt.Errorf("%w: timestamp drift %ds exceeds max allowed %v",
			ErrReplicationRejected, drift, maxDrift)
	}

	canonicalData, err := serializePayloadCanonical(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize canonical payload for verification: %w", err)
	}

	if !VerifyHMACSHA256(replicationKey, canonicalData, payload.Signature) {
		return nil, fmt.Errorf("%w: invalid HMAC signature", ErrReplicationRejected)
	}

	return payload.Secrets, nil
}

func serializePayloadCanonical(p *VaultSyncPayload) ([]byte, error) {
	// Canonical struct without signature field for deterministic signing
	type Canonical struct {
		NodeID    string        `json:"node_id"`
		ClusterID string        `json:"cluster_id"`
		Timestamp int64         `json:"timestamp"`
		Term      int           `json:"term"`
		Secrets   []VaultSecret `json:"secrets"`
	}
	c := Canonical{
		NodeID:    p.NodeID,
		ClusterID: p.ClusterID,
		Timestamp: p.Timestamp,
		Term:      p.Term,
		Secrets:   p.Secrets,
	}
	return json.Marshal(c)
}

func cloneJoinToken(t *ClusterJoinToken) *ClusterJoinToken {
	if t == nil {
		return nil
	}
	cp := *t
	return &cp
}
