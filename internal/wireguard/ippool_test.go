package wireguard

import (
	"testing"
	"time"
)

func TestNewIPPool_ValidAndInvalid(t *testing.T) {
	pool, err := NewIPPool("10.42.0.0/24", "10.42.0.1", 1*time.Hour)
	if err != nil {
		t.Fatalf("NewIPPool failed: %v", err)
	}
	if pool.GatewayIP() != "10.42.0.1" {
		t.Errorf("expected gateway IP 10.42.0.1, got %s", pool.GatewayIP())
	}

	// Invalid CIDR
	if _, err := NewIPPool("invalid", "", 1*time.Hour); err == nil {
		t.Errorf("expected error on invalid CIDR")
	}

	// Gateway outside subnet
	if _, err := NewIPPool("10.42.0.0/24", "192.168.1.1", 1*time.Hour); err == nil {
		t.Errorf("expected error when gateway IP outside subnet")
	}
}

func TestIPPool_AllocateAndRelease(t *testing.T) {
	pool, err := NewIPPool("10.42.0.0/24", "10.42.0.1", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Dynamic allocation for peer-1
	ip1, err := pool.Allocate("peer-1", "")
	if err != nil {
		t.Fatalf("Allocate failed for peer-1: %v", err)
	}
	if ip1 == "10.42.0.1" {
		t.Errorf("allocated IP should not be gateway IP")
	}

	// Dynamic allocation for peer-2
	ip2, err := pool.Allocate("peer-2", "")
	if err != nil {
		t.Fatalf("Allocate failed for peer-2: %v", err)
	}
	if ip1 == ip2 {
		t.Errorf("allocated IPs must be unique, got %s for both", ip1)
	}

	if pool.ActiveCount() != 2 {
		t.Errorf("expected 2 active leases, got %d", pool.ActiveCount())
	}

	// Release peer-1
	if !pool.Release("peer-1") {
		t.Errorf("expected Release(peer-1) to return true")
	}
	if pool.ActiveCount() != 1 {
		t.Errorf("expected 1 active lease after release, got %d", pool.ActiveCount())
	}

	// Non-existent release
	if pool.Release("unknown-peer") {
		t.Errorf("expected Release(unknown) to return false")
	}
}

func TestIPPool_PreferredIP(t *testing.T) {
	pool, err := NewIPPool("10.42.0.0/24", "10.42.0.1", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	ip, err := pool.Allocate("peer-static", "10.42.0.50")
	if err != nil {
		t.Fatalf("preferred allocation failed: %v", err)
	}
	if ip != "10.42.0.50" {
		t.Errorf("expected 10.42.0.50, got %s", ip)
	}

	// Collision attempt by peer-other
	if _, err := pool.Allocate("peer-other", "10.42.0.50"); err == nil {
		t.Errorf("expected collision error for already allocated IP")
	}

	// Outside subnet
	if _, err := pool.Allocate("peer-bad", "192.168.1.50"); err == nil {
		t.Errorf("expected error for IP outside subnet")
	}
}

func TestIPPool_ReclaimExpired(t *testing.T) {
	pool, err := NewIPPool("10.42.0.0/24", "10.42.0.1", 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.Allocate("peer-expiring", "")
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(30 * time.Millisecond)

	reclaimed := pool.ReclaimExpired()
	if reclaimed != 1 {
		t.Errorf("expected 1 reclaimed lease, got %d", reclaimed)
	}
	if pool.ActiveCount() != 0 {
		t.Errorf("expected 0 active leases, got %d", pool.ActiveCount())
	}
}
