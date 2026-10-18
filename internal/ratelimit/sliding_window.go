package ratelimit

import (
	"sync"
	"time"
)

// SlidingWindowCounter provides smooth rate limiting and bandwidth throttling
// across a moving time window with discrete sub-buckets to prevent boundary burst spikes.
type SlidingWindowCounter struct {
	mu          sync.Mutex
	windowSize  time.Duration
	bucketSize  time.Duration
	maxLimit    int64             // Maximum allowed units (requests or bytes) in window; 0 means unlimited
	buckets     map[int64]int64   // Key: bucket index (timestamp / bucketSize), Value: accumulated count
	lastPrune   time.Time
}

// NewSlidingWindowCounter creates a sliding window counter.
// Example: windowSize = 60s, bucketSize = 1s, maxLimit = 1000 requests.
func NewSlidingWindowCounter(windowSize time.Duration, bucketSize time.Duration, maxLimit int64) *SlidingWindowCounter {
	if windowSize <= 0 {
		windowSize = 60 * time.Second
	}
	if bucketSize <= 0 || bucketSize > windowSize {
		bucketSize = time.Second
	}
	return &SlidingWindowCounter{
		windowSize: windowSize,
		bucketSize: bucketSize,
		maxLimit:   maxLimit,
		buckets:    make(map[int64]int64),
		lastPrune:  time.Now(),
	}
}

// Allow attempts to record cost units at the current time.
// Returns (allowed, currentTotal, remaining).
func (s *SlidingWindowCounter) Allow(cost int64) (bool, int64, int64) {
	return s.AllowAt(cost, time.Now())
}

// AllowAt allows deterministic unit testing of time progression.
func (s *SlidingWindowCounter) AllowAt(cost int64, now time.Time) (bool, int64, int64) {
	if cost <= 0 {
		cost = 1
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.prune(now)

	currentSum := s.sum()

	// 0 maxLimit indicates tracking only (unlimited)
	if s.maxLimit > 0 && currentSum+cost > s.maxLimit {
		remaining := s.maxLimit - currentSum
		if remaining < 0 {
			remaining = 0
		}
		return false, currentSum, remaining
	}

	bucketIdx := now.UnixNano() / s.bucketSize.Nanoseconds()
	s.buckets[bucketIdx] += cost
	newTotal := currentSum + cost

	remaining := int64(0)
	if s.maxLimit > 0 {
		remaining = s.maxLimit - newTotal
		if remaining < 0 {
			remaining = 0
		}
	}
	return true, newTotal, remaining
}

// prune removes buckets that have fallen outside the rolling window. Must be called under s.mu.
func (s *SlidingWindowCounter) prune(now time.Time) {
	cutoffNano := now.Add(-s.windowSize).UnixNano()
	cutoffBucket := cutoffNano / s.bucketSize.Nanoseconds()

	for idx := range s.buckets {
		if idx <= cutoffBucket {
			delete(s.buckets, idx)
		}
	}
	s.lastPrune = now
}

// sum calculates total units in all active buckets. Must be called under s.mu.
func (s *SlidingWindowCounter) sum() int64 {
	var total int64
	for _, count := range s.buckets {
		total += count
	}
	return total
}

// Current returns the current total usage within the rolling window.
func (s *SlidingWindowCounter) Current() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(time.Now())
	return s.sum()
}

// UpdateLimit adjusts the maximum capacity for the window.
func (s *SlidingWindowCounter) UpdateLimit(newLimit int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxLimit = newLimit
}
