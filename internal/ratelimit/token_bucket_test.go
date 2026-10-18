package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestTokenBucket_BasicAllow(t *testing.T) {
	bucket := NewTokenBucket(10.0, 5.0) // 10 tokens/sec, max 5 burst

	// Consume 5 tokens immediately (burst capacity)
	for i := 0; i < 5; i++ {
		allowed, _ := bucket.Allow(1.0)
		if !allowed {
			t.Fatalf("expected token %d to be allowed", i)
		}
	}

	// 6th request should be denied
	allowed, retryAfter := bucket.Allow(1.0)
	if allowed {
		t.Fatalf("expected 6th request to be denied")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected positive retryAfter duration, got %v", retryAfter)
	}
}

func TestTokenBucket_RefillOverTime(t *testing.T) {
	baseTime := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	bucket := NewTokenBucket(10.0, 10.0) // 10 tokens/sec, capacity 10

	// Consume all 10 tokens at baseTime
	allowed, _ := bucket.AllowAt(10.0, baseTime)
	if !allowed {
		t.Fatalf("expected initial 10 tokens to be allowed")
	}

	// Advance 500ms -> should have 5 tokens replenished
	t1 := baseTime.Add(500 * time.Millisecond)
	allowed, _ = bucket.AllowAt(5.0, t1)
	if !allowed {
		t.Fatalf("expected 5 replenished tokens to be allowed after 500ms")
	}

	// Immediate next token should fail
	allowed, retryAfter := bucket.AllowAt(1.0, t1)
	if allowed {
		t.Fatalf("expected request to fail after consuming all replenished tokens")
	}
	if retryAfter < 50*time.Millisecond {
		t.Fatalf("unexpected retryAfter: %v", retryAfter)
	}

	// Advance 2 seconds -> should refill up to capacity (10 tokens, not 20)
	t2 := t1.Add(2 * time.Second)
	curr, cap := bucket.Peek()
	_ = curr
	_ = cap
	allowed, _ = bucket.AllowAt(10.0, t2)
	if !allowed {
		t.Fatalf("expected capacity 10 tokens to be available after full refill")
	}
}

func TestTokenBucket_Concurrency(t *testing.T) {
	bucket := NewTokenBucket(100.0, 50.0)
	var wg sync.WaitGroup
	workers := 20
	requestsPerWorker := 10

	allowedCount := 0
	var mu sync.Mutex

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := 0; r < requestsPerWorker; r++ {
				allowed, _ := bucket.Allow(1.0)
				if allowed {
					mu.Lock()
					allowedCount++
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	if allowedCount > 55 { // capacity is 50, a few might refill during concurrent execution
		t.Fatalf("allowed requests %d exceeded expected bound", allowedCount)
	}
}
