package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AuditEvent records an operational event with security and actor metadata.
type AuditEvent struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	Actor     string         `json:"actor"`
	ClientIP  string         `json:"client_ip"`
	Action    string         `json:"action"`
	Target    string         `json:"target"`
	Status    string         `json:"status"` // "success", "failed", "pending"
	Details   map[string]any `json:"details,omitempty"`
}

// Logger is a high-performance, thread-safe circular buffer holding up to capacity audit events.
type Logger struct {
	mu         sync.RWMutex
	capacity   int
	events     []AuditEvent
	start      int
	count      int
	totalCount atomic.Int64
}

// NewLogger initializes a circular audit logger with the requested capacity.
// If capacity <= 0, default 2000 is used. Capacity is capped at 10000.
func NewLogger(capacity int) *Logger {
	if capacity <= 0 {
		capacity = 2000
	}
	if capacity > 10000 {
		capacity = 10000
	}
	return &Logger{
		capacity: capacity,
		events:   make([]AuditEvent, capacity),
		start:    0,
		count:    0,
	}
}

// Log records a new audit event, automatically generating identifiers and UTC timestamps if empty.
func (l *Logger) Log(event AuditEvent) AuditEvent {
	if event.ID == "" {
		event.ID = generateAuditID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Actor == "" {
		event.Actor = "system"
	}
	if event.ClientIP == "" {
		event.ClientIP = "127.0.0.1"
	}
	if event.Status == "" {
		event.Status = "success"
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.count < l.capacity {
		idx := (l.start + l.count) % l.capacity
		l.events[idx] = event
		l.count++
	} else {
		l.events[l.start] = event
		l.start = (l.start + 1) % l.capacity
	}

	l.totalCount.Add(1)
	return event
}

// Recent returns up to `limit` events, optionally filtered by action, ordered oldest to newest.
// If actionFilter is "" or "all", all actions are returned.
func (l *Logger) Recent(limit int, actionFilter string) []AuditEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if limit <= 0 || limit > l.count {
		limit = l.count
	}

	actionFilter = strings.ToLower(strings.TrimSpace(actionFilter))
	var matched []AuditEvent

	// Walk from newest to oldest to collect the requested limit
	for i := l.count - 1; i >= 0; i-- {
		idx := (l.start + i) % l.capacity
		ev := l.events[idx]

		if actionFilter == "" || actionFilter == "all" || strings.ToLower(ev.Action) == actionFilter {
			matched = append(matched, ev)
			if len(matched) >= limit {
				break
			}
		}
	}

	// Reverse to chronological order (oldest -> newest)
	for i, j := 0, len(matched)-1; i < j; i, j = i+1, j-1 {
		matched[i], matched[j] = matched[j], matched[i]
	}

	return matched
}

// ExportNDJSON serializes audit events to newline-delimited JSON into the provided writer.
func (l *Logger) ExportNDJSON(w io.Writer, limit int, actionFilter string) error {
	events := l.Recent(limit, actionFilter)
	encoder := json.NewEncoder(w)

	for _, ev := range events {
		if err := encoder.Encode(ev); err != nil {
			return fmt.Errorf("failed to encode audit event to ndjson: %w", err)
		}
	}
	return nil
}

// TotalCount returns the cumulative count of logged events since initialization.
func (l *Logger) TotalCount() int64 {
	return l.totalCount.Load()
}

// Len returns the current number of events stored in the active buffer.
func (l *Logger) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.count
}

// Capacity returns the maximum capacity of the circular buffer.
func (l *Logger) Capacity() int {
	return l.capacity
}

// Clear wipes all recorded events and resets pointers.
func (l *Logger) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.start = 0
	l.count = 0
	for i := range l.events {
		l.events[i] = AuditEvent{}
	}
}

func generateAuditID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("aud_%d", time.Now().UnixNano())
	}
	return "aud_" + hex.EncodeToString(bytes)
}
