package healing

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var (
	ErrInvalidPolicy = errors.New("invalid healing policy configuration")
	containerPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
)

// PolicyConfig defines autonomous container remediation and self-healing parameters.
type PolicyConfig struct {
	Enabled                bool     `json:"enabled"`
	AutoRestartOOM         bool     `json:"auto_restart_oom"`
	AutoRestartCrashLoop   bool     `json:"auto_restart_crash_loop"`
	AutoRemediateUnhealthy bool     `json:"auto_remediate_unhealthy"`
	MaxAttempts            int      `json:"max_attempts"`
	BaseBackoffSec         int      `json:"base_backoff_sec"`
	MaxBackoffSec          int      `json:"max_backoff_sec"`
	JitterFactor           float64  `json:"jitter_factor"`
	CooldownSec            int      `json:"cooldown_sec"`
	ExcludedContainers     []string `json:"excluded_containers"`
}

// DefaultPolicyConfig returns production-grade baseline self-healing defaults.
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		Enabled:                true,
		AutoRestartOOM:         true,
		AutoRestartCrashLoop:   true,
		AutoRemediateUnhealthy: true,
		MaxAttempts:            3,
		BaseBackoffSec:         2,
		MaxBackoffSec:          60,
		JitterFactor:           0.25,
		CooldownSec:            300,
		ExcludedContainers:     make([]string, 0),
	}
}

// Validate checks configuration values against security and operational boundaries.
func (p PolicyConfig) Validate() error {
	if p.MaxAttempts < 1 || p.MaxAttempts > 20 {
		return fmt.Errorf("%w: max_attempts must be between 1 and 20, got %d", ErrInvalidPolicy, p.MaxAttempts)
	}
	if p.BaseBackoffSec < 1 || p.BaseBackoffSec > 60 {
		return fmt.Errorf("%w: base_backoff_sec must be between 1 and 60, got %d", ErrInvalidPolicy, p.BaseBackoffSec)
	}
	if p.MaxBackoffSec < 5 || p.MaxBackoffSec > 600 {
		return fmt.Errorf("%w: max_backoff_sec must be between 5 and 600, got %d", ErrInvalidPolicy, p.MaxBackoffSec)
	}
	if p.BaseBackoffSec > p.MaxBackoffSec {
		return fmt.Errorf("%w: base_backoff_sec (%d) cannot exceed max_backoff_sec (%d)", ErrInvalidPolicy, p.BaseBackoffSec, p.MaxBackoffSec)
	}
	if p.JitterFactor < 0.0 || p.JitterFactor > 1.0 {
		return fmt.Errorf("%w: jitter_factor must be between 0.0 and 1.0, got %f", ErrInvalidPolicy, p.JitterFactor)
	}
	if p.CooldownSec < 10 || p.CooldownSec > 86400 {
		return fmt.Errorf("%w: cooldown_sec must be between 10 and 86400, got %d", ErrInvalidPolicy, p.CooldownSec)
	}

	for _, idOrName := range p.ExcludedContainers {
		clean := strings.TrimSpace(idOrName)
		if clean == "" {
			continue
		}
		if !containerPattern.MatchString(clean) {
			return fmt.Errorf("%w: invalid excluded container identifier %q", ErrInvalidPolicy, clean)
		}
	}

	return nil
}

// PolicyStore provides thread-safe access and atomic updates to healing policies.
type PolicyStore struct {
	mu  sync.RWMutex
	cfg PolicyConfig
}

// NewPolicyStore constructs a thread-safe PolicyStore initialized with given settings.
func NewPolicyStore(cfg PolicyConfig) *PolicyStore {
	if err := cfg.Validate(); err != nil {
		cfg = DefaultPolicyConfig()
	}
	return &PolicyStore{
		cfg: cfg,
	}
}

// Get returns an immutable snapshot of the current policy configuration.
func (ps *PolicyStore) Get() PolicyConfig {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	excludedCopy := make([]string, len(ps.cfg.ExcludedContainers))
	copy(excludedCopy, ps.cfg.ExcludedContainers)

	snapshot := ps.cfg
	snapshot.ExcludedContainers = excludedCopy
	return snapshot
}

// Update validates and atomically replaces the active policy configuration.
func (ps *PolicyStore) Update(newCfg PolicyConfig) error {
	if err := newCfg.Validate(); err != nil {
		return err
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	excludedCopy := make([]string, len(newCfg.ExcludedContainers))
	copy(excludedCopy, newCfg.ExcludedContainers)
	newCfg.ExcludedContainers = excludedCopy

	ps.cfg = newCfg
	return nil
}
