package vault

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// LeaseManager manages the lifecycle of ephemeral secret access leases and automated shredding.
type LeaseManager struct {
	mu            sync.RWMutex
	leases        map[string]*SecretLease
	shreddedCount atomic.Int64
}

// NewLeaseManager creates an initialized LeaseManager.
func NewLeaseManager() *LeaseManager {
	return &LeaseManager{
		leases: make(map[string]*SecretLease),
	}
}

// IssueLease creates a time-bounded lease granting temporary read access to a secret.
func (lm *LeaseManager) IssueLease(secretID, secretKey, issuedTo string, ttl, maxTTL time.Duration) (*SecretLease, error) {
	if secretID == "" || secretKey == "" {
		return nil, errors.New("secret ID and secret key are required to issue lease")
	}
	if ttl < 10*time.Second {
		ttl = 10 * time.Second
	}
	if maxTTL < ttl {
		maxTTL = ttl
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	leaseID := GenerateLeaseID()
	now := time.Now().UTC()
	lease := &SecretLease{
		LeaseID:   leaseID,
		SecretID:  secretID,
		SecretKey: secretKey,
		IssuedTo:  issuedTo,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
		Renewable: true,
		MaxTTL:    maxTTL,
		Revoked:   false,
	}

	lm.leases[leaseID] = lease
	return cloneLease(lease), nil
}

// RenewLease extends the duration of an active lease, strictly enforcing MaxTTL from initial issuance.
func (lm *LeaseManager) RenewLease(leaseID string, extendDuration time.Duration) (*SecretLease, error) {
	if extendDuration <= 0 {
		return nil, errors.New("extend duration must be positive")
	}

	lm.mu.Lock()
	defer lm.mu.Unlock()

	lease, exists := lm.leases[leaseID]
	if !exists {
		return nil, ErrLeaseNotFound
	}
	if lease.Revoked {
		return nil, ErrLeaseRevoked
	}

	now := time.Now().UTC()
	if now.After(lease.ExpiresAt) {
		// Already expired, shred immediately
		delete(lm.leases, leaseID)
		lm.shreddedCount.Add(1)
		return nil, ErrLeaseExpired
	}

	newExpiry := lease.ExpiresAt.Add(extendDuration)
	hardLimit := lease.IssuedAt.Add(lease.MaxTTL)
	if newExpiry.After(hardLimit) {
		return nil, fmt.Errorf("%w: requested expiration %s exceeds hard limit %s",
			ErrLeaseMaxTTLExceeded, newExpiry.Format(time.RFC3339), hardLimit.Format(time.RFC3339))
	}

	lease.ExpiresAt = newExpiry
	return cloneLease(lease), nil
}

// RevokeLease immediately revokes and shreds an active lease.
func (lm *LeaseManager) RevokeLease(leaseID string) (*SecretLease, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	lease, exists := lm.leases[leaseID]
	if !exists {
		return nil, ErrLeaseNotFound
	}

	lease.Revoked = true
	delete(lm.leases, leaseID)
	lm.shreddedCount.Add(1)

	return cloneLease(lease), nil
}

// CheckAndShredExpired identifies all leases that have expired past 'now', removes them,
// increments shredded counter, and returns the list of shredded leases for security auditing.
func (lm *LeaseManager) CheckAndShredExpired(now time.Time) []*SecretLease {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	var shredded []*SecretLease
	for id, lease := range lm.leases {
		if now.After(lease.ExpiresAt) || lease.Revoked {
			lease.Revoked = true
			delete(lm.leases, id)
			lm.shreddedCount.Add(1)
			shredded = append(shredded, cloneLease(lease))
		}
	}

	return shredded
}

// GetLease retrieves an active lease by ID.
func (lm *LeaseManager) GetLease(leaseID string) (*SecretLease, bool) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	lease, exists := lm.leases[leaseID]
	if !exists {
		return nil, false
	}
	return cloneLease(lease), true
}

// ListActive returns a snapshot of currently valid, unexpired leases.
func (lm *LeaseManager) ListActive(now time.Time) []*SecretLease {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	active := make([]*SecretLease, 0, len(lm.leases))
	for _, lease := range lm.leases {
		if !lease.Revoked && now.Before(lease.ExpiresAt) {
			active = append(active, cloneLease(lease))
		}
	}
	return active
}

// ActiveCount returns count of unexpired, non-revoked leases.
func (lm *LeaseManager) ActiveCount(now time.Time) int {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	count := 0
	for _, lease := range lm.leases {
		if !lease.Revoked && now.Before(lease.ExpiresAt) {
			count++
		}
	}
	return count
}

// ShreddedCount returns cumulative count of shredded leases.
func (lm *LeaseManager) ShreddedCount() int64 {
	return lm.shreddedCount.Load()
}

func cloneLease(l *SecretLease) *SecretLease {
	if l == nil {
		return nil
	}
	cp := *l
	return &cp
}
