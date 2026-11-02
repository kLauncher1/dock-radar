package acme

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestCalculateDaysUntilExpireAndEvaluateStatus(t *testing.T) {
	now := time.Now()

	// 1. Expired 2 days ago
	expired := now.Add(-48 * time.Hour)
	if days := CalculateDaysUntilExpire(expired); days != 0 {
		t.Errorf("expected 0 days for expired cert, got %d", days)
	}
	if st := EvaluateStatus(expired, 30); st != CertStatusExpired {
		t.Errorf("expected CertStatusExpired, got %s", st)
	}

	// 2. Expiring in 10 days (threshold = 30)
	soon := now.Add(10 * 24 * time.Hour)
	if days := CalculateDaysUntilExpire(soon); days != 10 {
		t.Errorf("expected 10 days, got %d", days)
	}
	if st := EvaluateStatus(soon, 30); st != CertStatusExpiringSoon {
		t.Errorf("expected CertStatusExpiringSoon, got %s", st)
	}

	// 3. Valid with 60 days left
	valid := now.Add(60 * 24 * time.Hour)
	if days := CalculateDaysUntilExpire(valid); days != 60 {
		t.Errorf("expected 60 days, got %d", days)
	}
	if st := EvaluateStatus(valid, 30); st != CertStatusValid {
		t.Errorf("expected CertStatusValid, got %s", st)
	}
}

func TestRotationScheduler_FindDueRenewals(t *testing.T) {
	sched := NewRotationScheduler(30)
	if sched.ThresholdDays() != 30 {
		t.Fatalf("expected 30 days threshold")
	}

	now := time.Now()
	certs := []*ManagedCert{
		{
			Domain:    "valid.example.com",
			AutoRenew: true,
			NotAfter:  now.Add(50 * 24 * time.Hour),
		},
		{
			Domain:    "expiring.example.com",
			AutoRenew: true,
			NotAfter:  now.Add(15 * 24 * time.Hour),
		},
		{
			Domain:    "manual.example.com",
			AutoRenew: false, // Should NOT be picked
			NotAfter:  now.Add(5 * 24 * time.Hour),
		},
		{
			Domain:    "expired.example.com",
			AutoRenew: true,
			NotAfter:  now.Add(-2 * time.Hour),
		},
	}

	due := sched.FindDueRenewals(certs)
	if len(due) != 2 {
		t.Fatalf("expected 2 certs due for renewal, got %d", len(due))
	}
	if due[0].Domain != "expiring.example.com" || due[1].Domain != "expired.example.com" {
		t.Errorf("unexpected due certs: %v, %v", due[0].Domain, due[1].Domain)
	}

	// Update threshold
	sched.SetThresholdDays(60)
	due60 := sched.FindDueRenewals(certs)
	if len(due60) != 3 {
		t.Fatalf("expected 3 certs due for renewal with 60d threshold, got %d", len(due60))
	}
}

func TestRotationScheduler_LifecycleLoop(t *testing.T) {
	sched := NewRotationScheduler(30)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var invocations int64
	go sched.StartLifecycleLoop(ctx, 20*time.Millisecond, func() {
		atomic.AddInt64(&invocations, 1)
	})

	time.Sleep(65 * time.Millisecond)
	cancel()

	count := atomic.LoadInt64(&invocations)
	if count < 2 {
		t.Fatalf("expected at least 2 ticks, got %d", count)
	}
}
