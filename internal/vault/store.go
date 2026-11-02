package vault

import (
	"fmt"
	"time"
)

// StoreSecret encrypts and stores a new or updated configuration secret.
func (e *Engine) StoreSecret(key string, secretType SecretType, plaintext []byte, ttl time.Duration, tags, metadata map[string]string, actor, clientIP string) (*SecretSummary, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.cfg.Enabled {
		return nil, ErrVaultDisabled
	}
	if err := ValidateSecretKey(key); err != nil {
		return nil, err
	}
	if len(e.secrets) >= e.cfg.MaxSecrets {
		return nil, ErrSecretCapacityReached
	}

	activeKey := e.keyring[e.activeKeyID]
	if activeKey == nil || len(activeKey.KeyBytes) == 0 {
		return nil, ErrKeyRingEmpty
	}

	ciphertextB64, nonceHex, err := EncryptSecret(activeKey.KeyBytes, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}
	defer Zeroize(plaintext)
	e.encryptionsTotal.Add(1)

	now := time.Now().UTC()
	var expiresAt *time.Time
	if ttl > 0 {
		exp := now.Add(ttl)
		expiresAt = &exp
	}

	// Check if secret with this key already exists
	var secret *VaultSecret
	if existingID, exists := e.keyIndex[key]; exists {
		secret = e.secrets[existingID]
		secret.Ciphertext = ciphertextB64
		secret.Nonce = nonceHex
		secret.KeyID = e.activeKeyID
		secret.Version++
		secret.UpdatedAt = now
		secret.ExpiresAt = expiresAt
		secret.Type = secretType
		secret.Tags = tags
		secret.Metadata = metadata
	} else {
		secretID := GenerateSecretID()
		secret = &VaultSecret{
			ID:            secretID,
			Key:           key,
			Type:          secretType,
			Ciphertext:    ciphertextB64,
			Nonce:         nonceHex,
			KeyID:         e.activeKeyID,
			Version:       1,
			CreatedAt:     now,
			UpdatedAt:     now,
			ExpiresAt:     expiresAt,
			LeaseDuration: e.cfg.DefaultLeaseTTL,
			Tags:          tags,
			Metadata:      metadata,
		}
		e.secrets[secretID] = secret
		e.keyIndex[key] = secretID
	}

	e.logAudit("vault_secret_stored", secret.ID, actor, clientIP, "success", map[string]any{
		"key":     secret.Key,
		"version": secret.Version,
		"key_id":  secret.KeyID,
	})

	return toSummary(secret), nil
}

// ReadSecret decrypts secret payload, optionally issuing a time-bounded lease.
func (e *Engine) ReadSecret(idOrKey string, issueLease bool, leaseTTL time.Duration, actor, clientIP string) (*SecretLease, []byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.cfg.Enabled {
		return nil, nil, ErrVaultDisabled
	}

	secret := e.findSecretLocked(idOrKey)
	if secret == nil || secret.Shredded {
		return nil, nil, ErrSecretNotFound
	}

	now := time.Now().UTC()
	if secret.ExpiresAt != nil && now.After(*secret.ExpiresAt) {
		return nil, nil, ErrSecretNotFound
	}

	keyEntry := e.keyring[secret.KeyID]
	if keyEntry == nil || len(keyEntry.KeyBytes) == 0 {
		return nil, nil, fmt.Errorf("master key %s not found in keyring", secret.KeyID)
	}

	plaintext, err := DecryptSecret(keyEntry.KeyBytes, secret.Ciphertext, secret.Nonce)
	if err != nil {
		e.logAudit("vault_decrypt_failed", secret.ID, actor, clientIP, "failed", map[string]any{
			"key_id": secret.KeyID,
			"error":  err.Error(),
		})
		return nil, nil, err
	}
	e.decryptionsTotal.Add(1)

	var lease *SecretLease
	if issueLease {
		if leaseTTL <= 0 {
			leaseTTL = secret.LeaseDuration
		}
		var leaseErr error
		lease, leaseErr = e.leases.IssueLease(secret.ID, secret.Key, actor, leaseTTL, e.cfg.MaxLeaseTTL)
		if leaseErr == nil {
			secret.LeaseCount++
		}
	}

	e.logAudit("vault_secret_read", secret.ID, actor, clientIP, "success", map[string]any{
		"key":       secret.Key,
		"version":   secret.Version,
		"has_lease": lease != nil,
	})

	return lease, plaintext, nil
}

// DeleteSecret cryptographically shreds and removes a secret from the vault.
func (e *Engine) DeleteSecret(idOrKey, actor, clientIP string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	secret := e.findSecretLocked(idOrKey)
	if secret == nil {
		return ErrSecretNotFound
	}

	secret.Shredded = true
	delete(e.secrets, secret.ID)
	delete(e.keyIndex, secret.Key)

	e.logAudit("vault_secret_shredded", secret.ID, actor, clientIP, "success", map[string]any{
		"key": secret.Key,
	})
	return nil
}

func (e *Engine) findSecretLocked(idOrKey string) *VaultSecret {
	if s, exists := e.secrets[idOrKey]; exists {
		return s
	}
	if id, exists := e.keyIndex[idOrKey]; exists {
		return e.secrets[id]
	}
	return nil
}

func toSummary(s *VaultSecret) *SecretSummary {
	return &SecretSummary{
		ID:         s.ID,
		Key:        s.Key,
		Type:       s.Type,
		KeyID:      s.KeyID,
		Version:    s.Version,
		CreatedAt:  s.CreatedAt,
		UpdatedAt:  s.UpdatedAt,
		ExpiresAt:  s.ExpiresAt,
		LeaseCount: s.LeaseCount,
		Tags:       s.Tags,
		Shredded:   s.Shredded,
	}
}
