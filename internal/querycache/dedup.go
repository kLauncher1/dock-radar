package querycache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// EventDeduplicator suppresses redundant events across distributed mesh peers
// and Docker socket reconnects using a time-bounded sliding window.
type EventDeduplicator struct {
	mu      sync.Mutex
	cfg     DedupConfig
	seen    map[string]time.Time
	checked int64
	deduped int64
	unique  int64
}

// NewEventDeduplicator initializes an active sliding-window event deduplicator.
func NewEventDeduplicator(cfg DedupConfig) *EventDeduplicator {
	if err := ValidateDedupConfig(cfg); err != nil {
		cfg = DefaultDedupConfig()
	}
	return &EventDeduplicator{
		cfg:  cfg,
		seen: make(map[string]time.Time),
	}
}

// ComputeSignature calculates a deterministic unique fingerprint for an event.
func (d *EventDeduplicator) ComputeSignature(ev DockerEvent) string {
	if ev.ID != "" {
		return ev.ID
	}

	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s:%s:%s:%d:%s", ev.Type, ev.Action, ev.ActorID, ev.Time, ev.NodeID)
	return hex.EncodeToString(h.Sum(nil))
}

// IsDuplicate checks whether an incoming event has already been observed within the deduplication window.
func (d *EventDeduplicator) IsDuplicate(ev DockerEvent) bool {
	if !d.cfg.Enabled {
		return false
	}

	sig := d.ComputeSignature(ev)
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	d.checked++

	if seenAt, exists := d.seen[sig]; exists {
		if now.Sub(seenAt) <= d.cfg.Window {
			d.deduped++
			return true
		}
	}

	// Capacity protection: prune if table is saturated
	if len(d.seen) >= d.cfg.MaxTracked {
		d.pruneLocked(now)
		// If still over capacity, evict oldest entry
		if len(d.seen) >= d.cfg.MaxTracked {
			d.evictOldestLocked()
		}
	}

	d.seen[sig] = now
	d.unique++
	return false
}

// pruneLocked cleans up expired entries (caller must hold d.mu).
func (d *EventDeduplicator) pruneLocked(now time.Time) int {
	var expired []string
	for sig, seenAt := range d.seen {
		if now.Sub(seenAt) > d.cfg.Window {
			expired = append(expired, sig)
		}
	}
	for _, sig := range expired {
		delete(d.seen, sig)
	}
	return len(expired)
}

// evictOldestLocked removes the oldest recorded entry to bound memory growth.
func (d *EventDeduplicator) evictOldestLocked() {
	var oldestSig string
	var oldestTime time.Time

	first := true
	for sig, seenAt := range d.seen {
		if first || seenAt.Before(oldestTime) {
			oldestSig = sig
			oldestTime = seenAt
			first = false
		}
	}

	if oldestSig != "" {
		delete(d.seen, oldestSig)
	}
}

// PruneExpired purges stale records and returns the number of cleaned signatures.
func (d *EventDeduplicator) PruneExpired() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pruneLocked(time.Now())
}

// Stats returns a telemetry snapshot of deduplication activity.
func (d *EventDeduplicator) Stats() DedupStats {
	d.mu.Lock()
	defer d.mu.Unlock()

	return DedupStats{
		TotalChecked:  atomic.LoadInt64(&d.checked),
		TotalDeduped:  atomic.LoadInt64(&d.deduped),
		TotalUnique:   atomic.LoadInt64(&d.unique),
		ActiveTracked: len(d.seen),
	}
}

// Reset clears the deduplication table and resets telemetry counters.
func (d *EventDeduplicator) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.seen = make(map[string]time.Time)
	d.checked = 0
	d.deduped = 0
	d.unique = 0
}

// Config returns a copy of the deduplicator settings.
func (d *EventDeduplicator) Config() DedupConfig {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg
}

// UpdateConfig updates deduplication settings at runtime.
func (d *EventDeduplicator) UpdateConfig(cfg DedupConfig) error {
	if err := ValidateDedupConfig(cfg); err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg = cfg
	return nil
}
