package healing

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RemediationEvent captures a single autonomous container healing attempt or circuit-breaker transition.
type RemediationEvent struct {
	ID            string         `json:"id"`
	Timestamp     time.Time      `json:"timestamp"`
	ContainerID   string         `json:"container_id"`
	ContainerName string         `json:"container_name"`
	Image         string         `json:"image"`
	Trigger       string         `json:"trigger"`
	Attempt       int            `json:"attempt"`
	BackoffSec    float64        `json:"backoff_sec"`
	Action        string         `json:"action"`
	Status        string         `json:"status"`
	Message       string         `json:"message"`
	Details       map[string]any `json:"details,omitempty"`
}

// HistoryBuffer provides thread-safe circular storage for remediation audit events.
type HistoryBuffer struct {
	mu       sync.RWMutex
	capacity int
	entries  []RemediationEvent
	head     int
	count    int
	total    atomic.Int64
}

// NewHistoryBuffer initializes a bounded circular buffer with the specified capacity.
func NewHistoryBuffer(capacity int) *HistoryBuffer {
	if capacity <= 0 {
		capacity = 1000
	}
	return &HistoryBuffer{
		capacity: capacity,
		entries:  make([]RemediationEvent, capacity),
	}
}

// Record appends a remediation event into the circular buffer.
func (hb *HistoryBuffer) Record(event RemediationEvent) {
	if event.ID == "" {
		event.ID = generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	hb.mu.Lock()
	defer hb.mu.Unlock()

	hb.entries[hb.head] = event
	hb.head = (hb.head + 1) % hb.capacity
	if hb.count < hb.capacity {
		hb.count++
	}
	hb.total.Add(1)
}

// Recent returns up to limit recent events, optionally filtered by container ID and trigger.
func (hb *HistoryBuffer) Recent(limit int, containerFilter, triggerFilter string) []RemediationEvent {
	hb.mu.RLock()
	defer hb.mu.RUnlock()

	if limit <= 0 || limit > hb.capacity {
		limit = hb.count
	}

	containerFilter = strings.TrimSpace(containerFilter)
	triggerFilter = strings.TrimSpace(triggerFilter)

	results := make([]RemediationEvent, 0, limit)
	for i := 0; i < hb.count; i++ {
		idx := (hb.head - 1 - i + hb.capacity) % hb.capacity
		entry := hb.entries[idx]

		if containerFilter != "" && !strings.EqualFold(entry.ContainerID, containerFilter) &&
			!strings.Contains(strings.ToLower(entry.ContainerName), strings.ToLower(containerFilter)) {
			continue
		}

		if triggerFilter != "" && !strings.EqualFold(entry.Trigger, triggerFilter) {
			continue
		}

		results = append(results, entry)
		if len(results) >= limit {
			break
		}
	}

	return results
}

// TotalCount returns total lifetime events recorded.
func (hb *HistoryBuffer) TotalCount() int64 {
	return hb.total.Load()
}

// Len returns current number of buffered items.
func (hb *HistoryBuffer) Len() int {
	hb.mu.RLock()
	defer hb.mu.RUnlock()
	return hb.count
}

// Clear wipes all recorded events.
func (hb *HistoryBuffer) Clear() {
	hb.mu.Lock()
	defer hb.mu.Unlock()
	hb.entries = make([]RemediationEvent, hb.capacity)
	hb.head = 0
	hb.count = 0
}

func generateEventID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
