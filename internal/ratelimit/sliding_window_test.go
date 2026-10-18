package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestSlidingWindowCounter_BasicAllowAndLimit(t *testing.T) {
	windowSize := 10 * time.Second
	bucketSize := 1 * time.Second
	limit := int64(5)

	counter := NewSlidingWindowCounter(windowSize, bucketSize, limit)
	baseTime := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

	// Consume 5 requests at baseTime
	for i := 1; i <= 5; i++ {
		allowed, current, remaining := counter.AllowAt(1, baseTime)
		if !allowed {
			t.Fatalf("request %d should have been allowed", i)
		}
		if current != int64(i) {
			t.Fatalf("expected current %d, got %d", i, current)
		}
		if remaining != limit-int64(i) {
			t.Fatalf("expected remaining %d, got %d", limit-int64(i), remaining)
		}
	}

	// 6th request at same timestamp should be rejected
	allowed, current, remaining := counter.AllowAt(1, baseTime)
	if allowed {
		t.Fatalf("expected 6th request to be rejected")
	}
	if current != 5 {
		t.Fatalf("expected current 5, got %d", current)
	}
	if remaining != 0 {
		t.Fatalf("expected remaining 0, got %d", remaining)
	}

	// Advance time past the 10s window (to baseTime + 11s)
	t1 := baseTime.Add(11 * time.Second)
	allowed, current, remaining = counter.AllowAt(1, t1)
	if !allowed {
		t.Fatalf("request after window expiration should be allowed")
	}
	if current != 1 {
		t.Fatalf("expected reset current 1, got %d", current)
	}
	if remaining != 4 {
		t.Fatalf("expected remaining 4, got %d", remaining)
	}
}

func TestSlidingWindowCounter_BandwidthThrottling(t *testing.T) {
	// Window: 1 second, Max Bytes: 1024 (1 KB/s)
	counter := NewSlidingWindowCounter(1*time.Second, 100*time.Millisecond, 1024)
	baseTime := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

	// Ingest 500 bytes
	allowed, current, _ := counter.AllowAt(500, baseTime)
	if !allowed || current != 500 {
		t.Fatalf("expected 500 bytes allowed")
	}

	// Ingest 500 more bytes
	allowed, current, _ = counter.AllowAt(500, baseTime.Add(200*time.Millisecond))
	if !allowed || current != 1000 {
		t.Fatalf("expected 1000 bytes total")
	}

	// Ingest 100 bytes (would exceed 1024 limit) -> should be denied
	allowed, _, _ = counter.AllowAt(100, baseTime.Add(300*time.Millisecond))
	if allowed {
		t.Fatalf("expected bandwidth limit to trigger rejection")
	}
}

func TestSlidingWindowCounter_Concurrency(t *testing.T) {
	counter := NewSlidingWindowCounter(60*time.Second, 1*time.Second, 100)
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			counter.Allow(1)
		}()
	}

	wg.Wait()

	total := counter.Current()
	if total != 50 {
		t.Fatalf("expected total 50, got %d", total)
	}
}
