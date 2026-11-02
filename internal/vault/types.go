package vault

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Common error definitions for vault operations.
var (
	ErrSecretNotFound       = errors.New("vault secret not found")
	ErrSecretAlreadyExists  = errors.New("vault secret with this key already exists")
	ErrInvalidSecretKey     = errors.New("invalid secret key: must match ^[a-zA-Z0-9_\\-\\.\\/]{1,128}$")
	ErrInvalidSecretID      = errors.New("invalid secret id: must match ^sec_[a-zA-Z0-9]{8,32}$")
	ErrInvalidTokenID       = errors.New("invalid join token id: must match ^tok_[a-zA-Z0-9]{8,32}$")
	ErrInvalidLeaseID       = errors.New("invalid lease id: must match ^lse_[a-zA-Z0-9]{8,32}$")
	ErrLeaseNotFound        = errors.New("secret lease not found or expired")
	ErrLeaseExpired         = errors.New("secret lease has expired and been shredded")
	ErrLeaseRevoked         = errors.New("secret lease has been revoked")
	ErrLeaseMaxTTLExceeded  = errors.New("lease renewal exceeds maximum permitted TTL")
	ErrKeyRingEmpty         = errors.New("vault keyring has no active encryption key")
	ErrDecryptionFailed     = errors.New("secret decryption failed: message authentication tag mismatch")
	ErrJoinTokenInvalid     = errors.New("cluster join token is invalid or expired")
	ErrJoinTokenExhausted   = errors.New("cluster join token has reached its maximum use limit")
	ErrReplicationRejected  = errors.New("vault sync payload rejected: signature mismatch or timestamp drift")
	ErrVaultDisabled        = errors.New("vault engine is currently disabled")
	ErrSecretCapacityReached = errors.New("vault secret capacity limit reached")
)

var (
	secretKeyRegex  = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\/]{1,128}$`)
	secretIDRegex   = regexp.MustCompile(`^sec_[a-zA-Z0-9]{8,32}$`)
	tokenIDRegex    = regexp.MustCompile(`^tok_[a-zA-Z0-9]{8,32}$`)
	leaseIDRegex    = regexp.MustCompile(`^lse_[a-zA-Z0-9]{8,32}$`)
)

// SecretType categorizes the payload for operational and auditing clarity.
type SecretType string

const (
	SecretTypeGeneric     SecretType = "generic"
	SecretTypeEnvVar      SecretType = "env_var"
	SecretTypeCertificate SecretType = "tls_cert"
	SecretTypeToken       SecretType = "auth_token"
)

// VaultSecret represents an end-to-end encrypted secret entry stored in the vault.
type VaultSecret struct {
	ID            string            `json:"id"`
	Key           string            `json:"key"`
	Type          SecretType        `json:"type"`
	Ciphertext    string            `json:"ciphertext"` // Base64 encoded AES-256-GCM ciphertext + tag
	Nonce         string            `json:"nonce"`      // Hex encoded 12-byte GCM nonce
	KeyID         string            `json:"key_id"`     // KeyID in keyring that encrypted this secret
	Version       int               `json:"version"`    // Monotonic secret revision
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	LeaseDuration time.Duration     `json:"lease_duration"` // Default lease duration when accessed
	LeaseCount    int               `json:"lease_count"`    // Number of active leases currently issued
	Tags          map[string]string `json:"tags,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Shredded      bool              `json:"shredded"`
}

// SecretSummary provides a public view without revealing ciphertext or nonces.
type SecretSummary struct {
	ID         string            `json:"id"`
	Key        string            `json:"key"`
	Type       SecretType        `json:"type"`
	KeyID      string            `json:"key_id"`
	Version    int               `json:"version"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	ExpiresAt  *time.Time        `json:"expires_at,omitempty"`
	LeaseCount int               `json:"lease_count"`
	Tags       map[string]string `json:"tags,omitempty"`
	Shredded   bool              `json:"shredded"`
}

// SecretLease records a time-bounded ephemeral grant to read a secret.
type SecretLease struct {
	LeaseID    string        `json:"lease_id"`
	SecretID   string        `json:"secret_id"`
	SecretKey  string        `json:"secret_key"`
	IssuedTo   string        `json:"issued_to"`
	IssuedAt   time.Time     `json:"issued_at"`
	ExpiresAt  time.Time     `json:"expires_at"`
	Renewable  bool          `json:"renewable"`
	MaxTTL     time.Duration `json:"max_ttl"`
	Revoked    bool          `json:"revoked"`
	Plaintext  string        `json:"plaintext,omitempty"` // populated on issue/read only, zeroized in storage
}

// ClusterJoinToken represents a cryptographically verifiable ticket for adding cluster nodes.
type ClusterJoinToken struct {
	TokenID   string    `json:"token_id"`
	TokenHash string    `json:"token_hash"` // SHA-256 hex digest of plaintext token
	NodeRole  string    `json:"node_role"`  // admin, viewer, worker
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	UsesCount int       `json:"uses_count"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// MasterKeyEntry tracks an AES-256 key version in the vault keyring.
type MasterKeyEntry struct {
	KeyID     string    `json:"key_id"`
	KeyBytes  []byte    `json:"-"` // sensitive key material, shredded on retirement
	CreatedAt time.Time `json:"created_at"`
	RotatedAt time.Time `json:"rotated_at,omitempty"`
	State     string    `json:"state"` // active, retired, shredded
}

// VaultSyncPayload is the wire format for synchronized configuration replication across peers.
type VaultSyncPayload struct {
	NodeID    string        `json:"node_id"`
	ClusterID string        `json:"cluster_id"`
	Timestamp int64         `json:"timestamp"` // Unix timestamp in seconds
	Term      int           `json:"term"`
	Secrets   []VaultSecret `json:"secrets"`
	Signature string        `json:"signature"` // HMAC-SHA256 signature over payload
}

// VaultConfig defines tunable runtime parameters for the configuration vault.
type VaultConfig struct {
	Enabled             bool          `json:"enabled"`
	HardwareRootEnabled bool          `json:"hardware_root_enabled"`
	RotationInterval    time.Duration `json:"rotation_interval"`
	DefaultLeaseTTL     time.Duration `json:"default_lease_ttl"`
	MaxLeaseTTL         time.Duration `json:"max_lease_ttl"`
	MaxSecrets          int           `json:"max_secrets"`
	ReplicationSecret   string        `json:"replication_secret,omitempty"`
}

// VaultStatus provides real-time telemetry and health metrics of the vault.
type VaultStatus struct {
	Enabled             bool      `json:"enabled"`
	TotalSecrets        int       `json:"total_secrets"`
	ActiveLeases        int       `json:"active_leases"`
	ShreddedLeases      int       `json:"shredded_leases"`
	ActiveKeyID         string    `json:"active_key_id"`
	KeyAgeSeconds       int64     `json:"key_age_seconds"`
	NextRotationSeconds int64     `json:"next_rotation_seconds"`
	JoinTokensCount     int       `json:"join_tokens_count"`
	ReplicationsSynced  int       `json:"replications_synced"`
	HardwareRootActive  bool      `json:"hardware_root_active"`
	LastRotation        time.Time `json:"last_rotation"`
}

// DefaultVaultConfig initializes production-safe baseline defaults.
func DefaultVaultConfig() VaultConfig {
	return VaultConfig{
		Enabled:             true,
		HardwareRootEnabled: true,
		RotationInterval:    24 * time.Hour,
		DefaultLeaseTTL:     1 * time.Hour,
		MaxLeaseTTL:         24 * time.Hour,
		MaxSecrets:          1000,
		ReplicationSecret:   "",
	}
}

// ValidateSecretKey ensures secret keys conform to safe character subsets.
func ValidateSecretKey(key string) error {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return errors.New("secret key cannot be empty")
	}
	if !secretKeyRegex.MatchString(trimmed) {
		return fmt.Errorf("%w: '%s'", ErrInvalidSecretKey, trimmed)
	}
	return nil
}

// ValidateSecretID validates format of generated secret IDs.
func ValidateSecretID(id string) error {
	if !secretIDRegex.MatchString(id) {
		return fmt.Errorf("%w: '%s'", ErrInvalidSecretID, id)
	}
	return nil
}

// ValidateTokenID validates format of cluster join token IDs.
func ValidateTokenID(id string) error {
	if !tokenIDRegex.MatchString(id) {
		return fmt.Errorf("%w: '%s'", ErrInvalidTokenID, id)
	}
	return nil
}

// ValidateLeaseID validates format of ephemeral lease IDs.
func ValidateLeaseID(id string) error {
	if !leaseIDRegex.MatchString(id) {
		return fmt.Errorf("%w: '%s'", ErrInvalidLeaseID, id)
	}
	return nil
}

// ValidateVaultConfig ensures configuration values are within valid operational bounds.
func ValidateVaultConfig(cfg VaultConfig) error {
	if cfg.RotationInterval < 1*time.Minute || cfg.RotationInterval > 365*24*time.Hour {
		return errors.New("vault rotation interval must be between 1 minute and 365 days")
	}
	if cfg.DefaultLeaseTTL < 10*time.Second || cfg.DefaultLeaseTTL > cfg.MaxLeaseTTL {
		return errors.New("vault default lease TTL must be >= 10s and <= max lease TTL")
	}
	if cfg.MaxLeaseTTL < 1*time.Minute || cfg.MaxLeaseTTL > 720*time.Hour {
		return errors.New("vault max lease TTL must be between 1 minute and 720 hours")
	}
	if cfg.MaxSecrets < 10 || cfg.MaxSecrets > 50000 {
		return errors.New("vault max secrets capacity must be between 10 and 50,000")
	}
	return nil
}
