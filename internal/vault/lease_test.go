package vault

import (
	"errors"
	"testing"
	"time"
)

func TestLeaseManager_IssueAndGet(t *testing.T) {
	lm := NewLeaseManager()
	now := time.Now().UTC()

	lease, err := lm.IssueLease("sec_12345678", "API_KEY", "service-backend", 30*time.Minute, 2*time.Hour)
	if err != nil {
		t.Fatalf("failed to issue lease: %v", err)
	}

	if lease.LeaseID == "" || lease.SecretID != "sec_12345678" || lease.SecretKey != "API_KEY" {
		t.Fatalf("unexpected lease fields: %+v", lease)
	}
	if lease.ExpiresAt.Before(now.Add(29 * time.Minute)) {
		t.Fatalf("unexpected lease expiration: %v", lease.ExpiresAt)
	}

	fetched, ok := lm.GetLease(lease.LeaseID)
	if !ok || fetched.LeaseID != lease.LeaseID {
		t.Fatalf("failed to get active lease: %s", lease.LeaseID)
	}

	if lm.ActiveCount(now) != 1 {
		t.Fatalf("expected 1 active lease, got %d", lm.ActiveCount(now))
	}
}

func TestLeaseManager_Renew(t *testing.T) {
	lm := NewLeaseManager()
	lease, err := lm.IssueLease("sec_12345678", "API_KEY", "worker-1", 10*time.Minute, 30*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue lease: %v", err)
	}

	// Valid renewal
	renewed, err := lm.RenewLease(lease.LeaseID, 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to renew lease: %v", err)
	}
	if !renewed.ExpiresAt.After(lease.ExpiresAt) {
		t.Fatalf("expected extended expiration after renewal")
	}

	// Renewal exceeding MaxTTL
	_, err = lm.RenewLease(lease.LeaseID, 30*time.Minute)
	if err == nil || !errors.Is(err, ErrLeaseMaxTTLExceeded) {
		t.Fatalf("expected ErrLeaseMaxTTLExceeded, got: %v", err)
	}
}

func TestLeaseManager_Revoke(t *testing.T) {
	lm := NewLeaseManager()
	lease, err := lm.IssueLease("sec_12345678", "DB_PASS", "tester", 15*time.Minute, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to issue lease: %v", err)
	}

	revoked, err := lm.RevokeLease(lease.LeaseID)
	if err != nil {
		t.Fatalf("failed to revoke lease: %v", err)
	}
	if !revoked.Revoked {
		t.Fatalf("expected lease to be marked revoked")
	}

	if lm.ShreddedCount() != 1 {
		t.Fatalf("expected shredded count 1, got %d", lm.ShreddedCount())
	}

	_, ok := lm.GetLease(lease.LeaseID)
	if ok {
		t.Fatalf("expected revoked lease to be removed from active map")
	}
}

func TestLeaseManager_CheckAndShredExpired(t *testing.T) {
	lm := NewLeaseManager()
	now := time.Now().UTC()

	// Short-lived lease
	lease1, _ := lm.IssueLease("sec_1", "KEY1", "user1", 10*time.Second, 1*time.Minute)
	// Longer lease
	lease2, _ := lm.IssueLease("sec_2", "KEY2", "user2", 1*time.Hour, 2*time.Hour)

	// Advance time past lease1 expiration
	future := now.Add(20 * time.Second)
	shredded := lm.CheckAndShredExpired(future)

	if len(shredded) != 1 {
		t.Fatalf("expected 1 lease shredded, got %d", len(shredded))
	}
	if shredded[0].LeaseID != lease1.LeaseID {
		t.Fatalf("expected shredded lease ID %s, got %s", lease1.LeaseID, shredded[0].LeaseID)
	}

	if lm.ActiveCount(future) != 1 {
		t.Fatalf("expected 1 active lease remaining, got %d", lm.ActiveCount(future))
	}

	// Verify lease2 is still active
	if _, ok := lm.GetLease(lease2.LeaseID); !ok {
		t.Fatalf("expected lease2 to still be active")
	}
}
