package ratelimit

import (
	"testing"
	"time"
)

func TestIPBanStore_ManualBanAndUnban(t *testing.T) {
	store := NewIPBanStore(5, 10*time.Minute, true)
	testIP := "203.0.113.42"

	// Initially not banned
	banned, _ := store.IsBanned(testIP)
	if banned {
		t.Fatalf("expected IP to not be banned initially")
	}

	// Manually ban
	record, err := store.Ban(testIP, "DDoS simulation", 5*time.Minute, "test-node")
	if err != nil {
		t.Fatalf("failed to ban IP: %v", err)
	}
	if record.IP != testIP {
		t.Fatalf("expected IP %s, got %s", testIP, record.IP)
	}

	// Query ban status
	banned, queriedRecord := store.IsBanned(testIP)
	if !banned || queriedRecord == nil {
		t.Fatalf("expected IP to be reported banned")
	}

	// Active bans count
	if count := store.Count(); count != 1 {
		t.Fatalf("expected 1 active ban, got %d", count)
	}

	// Unban
	unbanned := store.Unban(testIP)
	if !unbanned {
		t.Fatalf("expected unban to return true")
	}

	banned, _ = store.IsBanned(testIP)
	if banned {
		t.Fatalf("expected IP to no longer be banned after unban")
	}
}

func TestIPBanStore_AutoBanOnThreshold(t *testing.T) {
	threshold := 3
	store := NewIPBanStore(threshold, 1*time.Hour, true)
	testIP := "198.51.100.25"

	// Record violations up to threshold - 1
	for i := 1; i < threshold; i++ {
		banned, _ := store.RecordViolation(testIP, "HTTP 429 threshold")
		if banned {
			t.Fatalf("should not be banned at violation count %d", i)
		}
	}

	// Reaching threshold should trigger auto-ban
	banned, record := store.RecordViolation(testIP, "HTTP 429 threshold")
	if !banned || record == nil {
		t.Fatalf("expected auto-ban to trigger at threshold %d", threshold)
	}

	isBanned, _ := store.IsBanned(testIP)
	if !isBanned {
		t.Fatalf("expected IP to be banned after auto-ban")
	}
}

func TestIPBanStore_LoopbackImmunity(t *testing.T) {
	store := NewIPBanStore(1, 1*time.Hour, true)

	// Attempts to ban 127.0.0.1 or ::1 should return error
	_, err := store.Ban("127.0.0.1", "test", time.Hour, "local")
	if err == nil {
		t.Fatalf("expected error banning IPv4 loopback")
	}

	_, err = store.Ban("::1", "test", time.Hour, "local")
	if err == nil {
		t.Fatalf("expected error banning IPv6 loopback")
	}

	banned, _ := store.RecordViolation("127.0.0.1", "test")
	if banned {
		t.Fatalf("loopback should never be auto-banned")
	}
}

func TestIPBanStore_ExpirationSweep(t *testing.T) {
	store := NewIPBanStore(5, 50*time.Millisecond, true)
	testIP := "203.0.113.99"

	_, err := store.Ban(testIP, "quick test", 50*time.Millisecond, "local")
	if err != nil {
		t.Fatalf("failed to ban: %v", err)
	}

	time.Sleep(70 * time.Millisecond)

	// Sweep expired
	purged := store.SweepExpired()
	if purged != 1 {
		t.Fatalf("expected 1 ban purged, got %d", purged)
	}

	banned, _ := store.IsBanned(testIP)
	if banned {
		t.Fatalf("expected expired ban to not be active")
	}
}
