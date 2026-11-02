package vault

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
)

// Engine is the master coordinator for the Zero-Knowledge Distributed Configuration Vault.
type Engine struct {
	mu                 sync.RWMutex
	cfg                VaultConfig
	nodeID             string
	secrets            map[string]*VaultSecret // keyed by ID
	keyIndex           map[string]string       // Key name -> Secret ID
	keyring            map[string]*MasterKeyEntry
	activeKeyID        string
	lastRotation       time.Time
	leases             *LeaseManager
	joinTokens         *JoinTokenManager
	replication        *ReplicationManager
	rotationsTotal     atomic.Int64
	encryptionsTotal   atomic.Int64
	decryptionsTotal   atomic.Int64
	replicationsSynced atomic.Int64
	hardwareRootActive bool
	auditLogger        *audit.Logger
	alertDispatcher    *alert.Dispatcher
	cancelFunc         context.CancelFunc
}

// NewEngine constructs and boots a Vault Engine with initial key derivation and keyring.
func NewEngine(cfg VaultConfig, auditLogger *audit.Logger, alertDispatcher *alert.Dispatcher, nodeID string) (*Engine, error) {
	if err := ValidateVaultConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid vault configuration: %w", err)
	}
	if nodeID == "" {
		nodeID = "dock-radar-node"
	}

	e := &Engine{
		cfg:             cfg,
		nodeID:          nodeID,
		secrets:         make(map[string]*VaultSecret),
		keyIndex:        make(map[string]string),
		keyring:         make(map[string]*MasterKeyEntry),
		leases:          NewLeaseManager(),
		joinTokens:      NewJoinTokenManager(),
		replication:     NewReplicationManager(),
		auditLogger:     auditLogger,
		alertDispatcher: alertDispatcher,
		lastRotation:    time.Now().UTC(),
	}

	// Initialize initial encryption key (Hardware-Rooted if enabled)
	var initialKey []byte
	var err error
	if cfg.HardwareRootEnabled {
		machineID := getMachineRootIdentifier()
		salt := []byte(nodeID + "-vault-hw-salt")
		initialKey, err = DeriveHardwareRootKey(salt, machineID, 1000)
		if err == nil {
			e.hardwareRootActive = true
		}
	}
	if initialKey == nil {
		initialKey, err = GenerateAES256Key()
		if err != nil {
			return nil, fmt.Errorf("failed to generate master key: %w", err)
		}
	}

	keyID := GenerateKeyID()
	e.activeKeyID = keyID
	e.keyring[keyID] = &MasterKeyEntry{
		KeyID:     keyID,
		KeyBytes:  initialKey,
		CreatedAt: e.lastRotation,
		State:     "active",
	}

	return e, nil
}

// Start spawns background ticker for automated lease shredding and key rotation.
func (e *Engine) Start(ctx context.Context) {
	e.mu.Lock()
	if e.cancelFunc != nil {
		e.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	e.cancelFunc = cancel
	e.mu.Unlock()

	go e.runMaintenanceLoop(runCtx)
}

// Stop cleanly terminates background workers.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancelFunc != nil {
		e.cancelFunc()
		e.cancelFunc = nil
	}
}

func (e *Engine) runMaintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.performMaintenance()
		}
	}
}

func (e *Engine) performMaintenance() {
	now := time.Now().UTC()

	// 1. Ephemeral lease expiration check & automated shredding
	shredded := e.leases.CheckAndShredExpired(now)
	for _, l := range shredded {
		e.logAudit("vault_lease_shredded", l.LeaseID, "system", "127.0.0.1", "success", map[string]any{
			"secret_id":  l.SecretID,
			"secret_key": l.SecretKey,
			"issued_to":  l.IssuedTo,
			"expired_at": l.ExpiresAt.Format(time.RFC3339),
		})
	}

	// 2. Automatic key rotation check
	e.mu.Lock()
	shouldRotate := e.cfg.Enabled && e.cfg.RotationInterval > 0 && now.Sub(e.lastRotation) >= e.cfg.RotationInterval
	e.mu.Unlock()

	if shouldRotate {
		_, _ = e.RotateMasterKey("system-auto-rotator", "127.0.0.1")
	}
}

// RotateMasterKey generates a new key in the keyring and seamlessly re-encrypts all stored secrets.
func (e *Engine) RotateMasterKey(actor, clientIP string) (*MasterKeyEntry, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	newKeyBytes, err := GenerateAES256Key()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new master key: %w", err)
	}

	newKeyID := GenerateKeyID()
	now := time.Now().UTC()

	// Re-encrypt all active secrets under the new active key
	reencrypted := 0
	for _, sec := range e.secrets {
		if sec.Shredded {
			continue
		}
		oldKeyEntry := e.keyring[sec.KeyID]
		if oldKeyEntry == nil {
			continue
		}
		plaintext, err := DecryptSecret(oldKeyEntry.KeyBytes, sec.Ciphertext, sec.Nonce)
		if err != nil {
			continue
		}
		newCipher, newNonce, err := EncryptSecret(newKeyBytes, plaintext)
		Zeroize(plaintext)
		if err != nil {
			continue
		}
		sec.Ciphertext = newCipher
		sec.Nonce = newNonce
		sec.KeyID = newKeyID
		sec.Version++
		sec.UpdatedAt = now
		reencrypted++
	}

	// Retire old active key
	if oldKey := e.keyring[e.activeKeyID]; oldKey != nil {
		oldKey.State = "retired"
		oldKey.RotatedAt = now
	}

	newEntry := &MasterKeyEntry{
		KeyID:     newKeyID,
		KeyBytes:  newKeyBytes,
		CreatedAt: now,
		State:     "active",
	}
	e.keyring[newKeyID] = newEntry
	e.activeKeyID = newKeyID
	e.lastRotation = now
	e.rotationsTotal.Add(1)

	e.logAudit("vault_key_rotated", newKeyID, actor, clientIP, "success", map[string]any{
		"reencrypted_secrets": reencrypted,
	})

	if e.alertDispatcher != nil {
		_ = e.alertDispatcher.Dispatch(context.Background(), alert.Event{
			EventType: "vault_key_rotated",
			Level:     alert.LevelInfo,
			Source:    "vault",
			Message:   fmt.Sprintf("Vault master key rotated to %s (%d secrets re-encrypted)", newKeyID, reencrypted),
			Timestamp: now,
		})
	}

	return newEntry, nil
}

// CreateJoinToken issues a cluster join ticket for provisioning mesh peer nodes.
func (e *Engine) CreateJoinToken(role string, ttl time.Duration, maxUses int, actor, clientIP string) (string, *ClusterJoinToken, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	plain, tok, err := e.joinTokens.CreateToken(role, ttl, maxUses, actor)
	if err != nil {
		return "", nil, err
	}

	e.logAudit("vault_join_token_created", tok.TokenID, actor, clientIP, "success", map[string]any{
		"role":     tok.NodeRole,
		"max_uses": tok.MaxUses,
	})
	return plain, tok, nil
}

// RevokeJoinToken revokes a join token.
func (e *Engine) RevokeJoinToken(tokenID, actor, clientIP string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	err := e.joinTokens.RevokeToken(tokenID)
	if err != nil {
		return err
	}

	e.logAudit("vault_join_token_revoked", tokenID, actor, clientIP, "success", nil)
	return nil
}

// AcquireLease issues an explicit lease on a secret.
func (e *Engine) AcquireLease(idOrKey string, ttl time.Duration, actor, clientIP string) (*SecretLease, error) {
	lease, plaintext, err := e.ReadSecret(idOrKey, true, ttl, actor, clientIP)
	if err != nil {
		return nil, err
	}
	Zeroize(plaintext)
	return lease, nil
}

// RenewLease extends an active secret lease.
func (e *Engine) RenewLease(leaseID string, extendDuration time.Duration, actor, clientIP string) (*SecretLease, error) {
	lease, err := e.leases.RenewLease(leaseID, extendDuration)
	if err != nil {
		return nil, err
	}
	e.logAudit("vault_lease_renewed", leaseID, actor, clientIP, "success", map[string]any{
		"new_expiry": lease.ExpiresAt.Format(time.RFC3339),
	})
	return lease, nil
}

// RevokeLease revokes an active lease.
func (e *Engine) RevokeLease(leaseID, actor, clientIP string) (*SecretLease, error) {
	lease, err := e.leases.RevokeLease(leaseID)
	if err != nil {
		return nil, err
	}
	e.logAudit("vault_lease_revoked", leaseID, actor, clientIP, "success", nil)
	return lease, nil
}

// ListSecrets returns public metadata summaries for all stored secrets.
func (e *Engine) ListSecrets(typeFilter string) []*SecretSummary {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now().UTC()
	var list []*SecretSummary
	for _, sec := range e.secrets {
		if sec.Shredded {
			continue
		}
		if typeFilter != "" && string(sec.Type) != typeFilter {
			continue
		}
		if sec.ExpiresAt != nil && now.After(*sec.ExpiresAt) {
			continue
		}
		list = append(list, toSummary(sec))
	}
	return list
}

// ListLeases returns currently active leases.
func (e *Engine) ListLeases() []*SecretLease {
	return e.leases.ListActive(time.Now().UTC())
}

// ListJoinTokens returns cluster join tokens.
func (e *Engine) ListJoinTokens() []*ClusterJoinToken {
	return e.joinTokens.ListTokens()
}

// ExportSyncPayload creates an authenticated replication digest of all encrypted secrets.
func (e *Engine) ExportSyncPayload() (*VaultSyncPayload, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	activeKey := e.keyring[e.activeKeyID]
	if activeKey == nil {
		return nil, ErrKeyRingEmpty
	}

	var secretsList []VaultSecret
	for _, s := range e.secrets {
		if !s.Shredded {
			secretsList = append(secretsList, *s)
		}
	}

	repKey := []byte(e.cfg.ReplicationSecret)
	if len(repKey) == 0 {
		repKey = activeKey.KeyBytes
	}

	return e.replication.BuildSyncPayload(e.nodeID, "dock-radar-cluster", 1, secretsList, repKey)
}

// IngestSyncPayload validates and ingests replication payload from peer.
func (e *Engine) IngestSyncPayload(payload *VaultSyncPayload, actor, clientIP string) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	activeKey := e.keyring[e.activeKeyID]
	if activeKey == nil {
		return 0, ErrKeyRingEmpty
	}

	repKey := []byte(e.cfg.ReplicationSecret)
	if len(repKey) == 0 {
		repKey = activeKey.KeyBytes
	}

	secrets, err := e.replication.VerifyAndIngest(payload, repKey, 60*time.Second)
	if err != nil {
		return 0, err
	}

	ingested := 0
	for _, s := range secrets {
		secCopy := s
		e.secrets[s.ID] = &secCopy
		e.keyIndex[s.Key] = s.ID
		ingested++
	}
	e.replicationsSynced.Add(int64(ingested))

	e.logAudit("vault_replication_ingested", payload.NodeID, actor, clientIP, "success", map[string]any{
		"secrets_count": ingested,
	})

	return ingested, nil
}

// Status returns runtime status metrics.
func (e *Engine) Status() VaultStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now().UTC()
	keyAge := int64(now.Sub(e.lastRotation).Seconds())
	nextRot := int64(0)
	if e.cfg.RotationInterval > 0 {
		rem := e.cfg.RotationInterval - now.Sub(e.lastRotation)
		if rem > 0 {
			nextRot = int64(rem.Seconds())
		}
	}

	return VaultStatus{
		Enabled:             e.cfg.Enabled,
		TotalSecrets:        len(e.secrets),
		ActiveLeases:        e.leases.ActiveCount(now),
		ShreddedLeases:      int(e.leases.ShreddedCount()),
		ActiveKeyID:         e.activeKeyID,
		KeyAgeSeconds:       keyAge,
		NextRotationSeconds: nextRot,
		JoinTokensCount:     len(e.joinTokens.ListTokens()),
		ReplicationsSynced:  int(e.replicationsSynced.Load()),
		HardwareRootActive:  e.hardwareRootActive,
		LastRotation:        e.lastRotation,
	}
}

// Config returns active configuration.
func (e *Engine) Config() VaultConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// UpdateConfig applies configuration changes at runtime.
func (e *Engine) UpdateConfig(newCfg VaultConfig, actor, clientIP string) error {
	if err := ValidateVaultConfig(newCfg); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = newCfg
	e.logAudit("vault_config_updated", "vault", actor, clientIP, "success", nil)
	return nil
}

func (e *Engine) logAudit(action, target, actor, clientIP, status string, details map[string]any) {
	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:   action,
			Target:   target,
			Actor:    actor,
			ClientIP: clientIP,
			Status:   status,
			Details:  details,
		})
	}
}

func getMachineRootIdentifier() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "dock-radar-local-machine"
}
