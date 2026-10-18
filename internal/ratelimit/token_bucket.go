package ratelimit

import (
	"math"
	"sync"
	"time"
)

// TokenBucket implements a high-performance, thread-safe token bucket algorithm
// supporting fractional token replenishment and burst handling.
type TokenBucket struct {
	mu         sync.Mutex
	rate       float64   // Tokens added per second
	capacity   float64   // Maximum burst capacity
	tokens     float64   // Current token balance
	lastRefill time.Time // Timestamp of previous refill
}

// NewTokenBucket creates and initializes a TokenBucket starting at full capacity.
func NewTokenBucket(rate float64, capacity float64) *TokenBucket {
	if rate <= 0 {
		rate = 1.0
	}
	if capacity <= 0 {
		capacity = 1.0
	}
	return &TokenBucket{
		rate:       rate,
		capacity:   capacity,
		tokens:     capacity,
		lastRefill: time.Now(),
	}
}

// Allow attempts to consume the requested cost in tokens.
// Returns (true, 0) if permitted, or (false, retryAfter) if exhausted.
func (b *TokenBucket) Allow(cost float64) (bool, time.Duration) {
	return b.AllowAt(cost, time.Now())
}

// AllowAt performs the token evaluation at a specific timestamp (enabling deterministic tests).
func (b *TokenBucket) AllowAt(cost float64, now time.Time) (bool, time.Duration) {
	if cost <= 0 {
		cost = 1.0
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.refill(now)

	if b.tokens >= cost {
		b.tokens -= cost
		return true, 0
	}

	missing := cost - b.tokens
	retrySeconds := missing / b.rate
	retryAfter := time.Duration(math.Ceil(retrySeconds * float64(time.Second)))
	if retryAfter < time.Millisecond {
		retryAfter = time.Millisecond
	}
	return false, retryAfter
}

// refill adds accrued tokens based on elapsed duration since lastRefill. Must be called while holding mu.
func (b *TokenBucket) refill(now time.Time) {
	if now.Before(b.lastRefill) {
		// Clock skew or monotonic backwards jump guard
		b.lastRefill = now
		return
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now

	delta := elapsed * b.rate
	b.tokens = math.Min(b.capacity, b.tokens+delta)
}

// Peek returns the current token balance and capacity after updating with current elapsed time.
func (b *TokenBucket) Peek() (current float64, capacity float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill(time.Now())
	return b.tokens, b.capacity
}

// UpdateConfig dynamically updates the refill rate and capacity.
func (b *TokenBucket) UpdateConfig(newRate float64, newCapacity float64) {
	if newRate <= 0 {
		newRate = 1.0
	}
	if newCapacity <= 0 {
		newCapacity = 1.0
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.refill(time.Now())
	b.rate = newRate
	b.capacity = newCapacity
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
}
