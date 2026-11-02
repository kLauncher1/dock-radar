package acme

import (
	"context"
	"math"
	"sync"
	"time"
)

// RotationScheduler evaluates certificate expiration deadlines and identifies renewal candidates.
type RotationScheduler struct {
	mu            sync.RWMutex
	thresholdDays int
	lastCheckAt   time.Time
}

// NewRotationScheduler creates a rotation scheduler with expiration thresholds.
func NewRotationScheduler(thresholdDays int) *RotationScheduler {
	if thresholdDays <= 0 {
		thresholdDays = 30
	}
	return &RotationScheduler{
		thresholdDays: thresholdDays,
	}
}

// SetThresholdDays updates the days-until-expiration renewal threshold.
func (s *RotationScheduler) SetThresholdDays(days int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if days > 0 {
		s.thresholdDays = days
	}
}

// ThresholdDays returns the active renewal threshold in days.
func (s *RotationScheduler) ThresholdDays() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.thresholdDays
}

// CalculateDaysUntilExpire returns the remaining lifetime of a certificate in integer days.
func CalculateDaysUntilExpire(notAfter time.Time) int {
	now := time.Now()
	diff := notAfter.Sub(now)
	if diff <= 0 {
		return 0
	}
	days := math.Ceil(diff.Hours() / 24.0)
	return int(days)
}

// EvaluateStatus determines the lifecycle status of a certificate based on its expiration.
func EvaluateStatus(notAfter time.Time, thresholdDays int) CertStatus {
	now := time.Now()
	if now.After(notAfter) {
		return CertStatusExpired
	}
	daysLeft := CalculateDaysUntilExpire(notAfter)
	if daysLeft <= thresholdDays {
		return CertStatusExpiringSoon
	}
	return CertStatusValid
}

// FindDueRenewals inspects a slice of managed certificates and returns those requiring renewal.
func (s *RotationScheduler) FindDueRenewals(certs []*ManagedCert) []*ManagedCert {
	s.mu.Lock()
	s.lastCheckAt = time.Now()
	threshold := s.thresholdDays
	s.mu.Unlock()

	var due []*ManagedCert
	for _, c := range certs {
		if c == nil || !c.AutoRenew {
			continue
		}
		if c.Status == CertStatusRenewing {
			continue
		}

		c.DaysUntilExpire = CalculateDaysUntilExpire(c.NotAfter)
		newStatus := EvaluateStatus(c.NotAfter, threshold)
		if c.Status != CertStatusFailed || newStatus == CertStatusExpired {
			c.Status = newStatus
		}

		if newStatus == CertStatusExpiringSoon || newStatus == CertStatusExpired {
			due = append(due, c)
		}
	}
	return due
}

// LastCheck returns the timestamp of the last evaluation sweep.
func (s *RotationScheduler) LastCheck() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastCheckAt
}

// StartLifecycleLoop periodically executes the renewal callback until ctx is cancelled.
func (s *RotationScheduler) StartLifecycleLoop(ctx context.Context, interval time.Duration, tickFn func()) {
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial check on startup
	tickFn()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tickFn()
		}
	}
}
