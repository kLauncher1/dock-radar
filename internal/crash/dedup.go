package crash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// DedupEntry tracks temporal aggregation metrics for a distinct crash signature.
type DedupEntry struct {
	Signature string    `json:"signature"`
	ReportID  string    `json:"report_id"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	LastAlert time.Time `json:"last_alert"`
	Count     int       `json:"count"`
}

// DedupEngine manages sliding-window deduplication and alert storm suppression for container crashes.
type DedupEngine struct {
	mu            sync.RWMutex
	window        time.Duration
	maxSignatures int
	entries       map[string]*DedupEntry
}

// NewDedupEngine initializes a thread-safe deduplication engine.
func NewDedupEngine(window time.Duration, maxSignatures int) *DedupEngine {
	if window <= 0 {
		window = 15 * time.Minute
	}
	if maxSignatures <= 0 {
		maxSignatures = 1000
	}
	return &DedupEngine{
		window:        window,
		maxSignatures: maxSignatures,
		entries:       make(map[string]*DedupEntry),
	}
}

// ComputeCrashSignature generates a deterministic SHA-256 fingerprint for a crash based on its
// signal, root cause classification, container image, and top execution stack frames.
func ComputeCrashSignature(report *CrashReport) string {
	if report == nil {
		return "crash_sig_0000000000000000"
	}

	h := sha256.New()
	fmt.Fprintf(h, "sig:%s|cause:%s|img:%s|", report.Signal, report.RootCause, report.Image)

	// Hash up to 4 top stack frames
	frames := report.Backtrace.Frames
	if len(frames) > 4 {
		frames = frames[:4]
	}
	for _, f := range frames {
		fn := strings.TrimSpace(f.Function)
		mod := strings.TrimSpace(f.Module)
		if fn == "" {
			fn = fmt.Sprintf("sub_%x", f.IP&^0xfff) // Normalize to page base
		}
		fmt.Fprintf(h, "fn:%s|mod:%s|", fn, mod)
	}

	digest := hex.EncodeToString(h.Sum(nil))
	return "crash_sig_" + digest[:16]
}

// Process evaluates a crash report against active deduplication signatures.
// Returns isDuplicate, current count, and whether an alert webhook should be dispatched.
func (e *DedupEngine) Process(report *CrashReport, now time.Time) (isDuplicate bool, count int, shouldAlert bool) {
	if report == nil {
		return false, 0, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	sig := report.Signature
	if sig == "" {
		sig = ComputeCrashSignature(report)
		report.Signature = sig
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	entry, exists := e.entries[sig]
	if exists && now.Sub(entry.LastSeen) <= e.window {
		entry.Count++
		entry.LastSeen = now

		report.DeduplicatedCount = entry.Count
		report.FirstSeen = entry.FirstSeen
		report.LastSeen = entry.LastSeen

		// Alert throttling: alert on initial crash, then on 5th, 25th, and every 100th occurrence,
		// or if at least 30 minutes have elapsed since the last alert for this signature.
		alert := false
		if entry.Count == 5 || entry.Count == 25 || (entry.Count%100 == 0) || now.Sub(entry.LastAlert) >= 30*time.Minute {
			alert = true
			entry.LastAlert = now
		}

		return true, entry.Count, alert
	}

	// New or expired signature
	if len(e.entries) >= e.maxSignatures {
		e.evictOldestLocked()
	}

	newEntry := &DedupEntry{
		Signature: sig,
		ReportID:  report.ID,
		FirstSeen: now,
		LastSeen:  now,
		LastAlert: now,
		Count:     1,
	}
	e.entries[sig] = newEntry

	report.DeduplicatedCount = 1
	report.FirstSeen = now
	report.LastSeen = now

	return false, 1, true
}

// UniqueCount returns the number of active distinct crash signatures.
func (e *DedupEngine) UniqueCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.entries)
}

// Entries returns a copy of all current deduplication records.
func (e *DedupEngine) Entries() []*DedupEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*DedupEntry, 0, len(e.entries))
	for _, entry := range e.entries {
		copyEntry := *entry
		result = append(result, &copyEntry)
	}
	return result
}

// SweepExpired removes entries older than the deduplication window relative to the cutoff time.
func (e *DedupEngine) SweepExpired(cutoff time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	evicted := 0
	for sig, entry := range e.entries {
		if cutoff.Sub(entry.LastSeen) > e.window {
			delete(e.entries, sig)
			evicted++
		}
	}
	return evicted
}

// evictOldestLocked evicts the entry with the oldest LastSeen timestamp to respect bounded capacity.
func (e *DedupEngine) evictOldestLocked() {
	var oldestSig string
	var oldestTime time.Time

	for sig, entry := range e.entries {
		if oldestSig == "" || entry.LastSeen.Before(oldestTime) {
			oldestSig = sig
			oldestTime = entry.LastSeen
		}
	}

	if oldestSig != "" {
		delete(e.entries, oldestSig)
	}
}
