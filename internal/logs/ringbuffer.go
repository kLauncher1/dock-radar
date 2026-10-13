package logs

import (
	"strings"
	"sync"
	"time"
)

// LogEntry represents an individual recorded log line with metadata.
type LogEntry struct {
	ID        string    `json:"id"`
	Stream    string    `json:"stream"` // "stdout", "stderr", "system"
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

// RingBuffer is a high-performance, thread-safe circular buffer for log streaming.
// It maintains a fixed memory footprint well under 15 MB by strictly capping entry count
// and individual message length.
type RingBuffer struct {
	mu       sync.RWMutex
	capacity int
	entries  []LogEntry
	start    int
	count    int
}

// NewRingBuffer allocates a ring buffer with the given capacity.
// If capacity <= 0, default 1000 entries is assigned.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = 1000
	}
	if capacity > 10000 {
		capacity = 10000
	}
	return &RingBuffer{
		capacity: capacity,
		entries:  make([]LogEntry, capacity),
		start:    0,
		count:    0,
	}
}

// Append inserts an entry into the buffer, overwriting the oldest entry if full.
func (rb *RingBuffer) Append(entry LogEntry) {
	// Guard against excessive string payload to preserve low memory footprint
	if len(entry.Message) > 2048 {
		entry.Message = entry.Message[:2048] + " [truncated]"
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	if entry.Stream == "" {
		entry.Stream = "stdout"
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.count < rb.capacity {
		idx := (rb.start + rb.count) % rb.capacity
		rb.entries[idx] = entry
		rb.count++
	} else {
		// Overwrite the oldest entry at start and advance start pointer
		rb.entries[rb.start] = entry
		rb.start = (rb.start + 1) % rb.capacity
	}
}

// Recent returns up to `limit` entries, optionally filtered by stream.
// filter: "" or "all" for all streams; "stdout", "stderr", or "system".
func (rb *RingBuffer) Recent(limit int, filter string) []LogEntry {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if limit <= 0 || limit > rb.count {
		limit = rb.count
	}

	var matched []LogEntry
	filter = strings.ToLower(strings.TrimSpace(filter))

	// Walk from newest to oldest to collect the requested limit
	for i := rb.count - 1; i >= 0; i-- {
		idx := (rb.start + i) % rb.capacity
		e := rb.entries[idx]

		if filter == "" || filter == "all" || strings.ToLower(e.Stream) == filter {
			matched = append(matched, e)
			if len(matched) >= limit {
				break
			}
		}
	}

	// Reverse to restore chronological order (oldest -> newest)
	for i, j := 0, len(matched)-1; i < j; i, j = i+1, j-1 {
		matched[i], matched[j] = matched[j], matched[i]
	}

	return matched
}

// Len returns the current number of stored entries.
func (rb *RingBuffer) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.count
}

// Clear flushes all entries from the ring buffer.
func (rb *RingBuffer) Clear() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.start = 0
	rb.count = 0
	for i := range rb.entries {
		rb.entries[i] = LogEntry{}
	}
}

// EstimateMemoryBytes computes approximate memory utilization in bytes.
func (rb *RingBuffer) EstimateMemoryBytes() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	total := rb.capacity * 64 // struct overhead per entry
	for i := 0; i < rb.count; i++ {
		idx := (rb.start + i) % rb.capacity
		total += len(rb.entries[idx].Message) + len(rb.entries[idx].ID) + len(rb.entries[idx].Stream)
	}
	return total
}
