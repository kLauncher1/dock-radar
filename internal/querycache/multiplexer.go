package querycache

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// subscriberHandle tracks an active event listener and its bounded buffer channel.
type subscriberHandle struct {
	id      string
	filter  EventFilter
	ch      chan DockerEvent
	dropped int64
	closed  bool
}

// EventMultiplexer distributes Docker engine and cluster events to multiple subscribers
// with dynamic backpressure regulation and zero-blocking guarantees.
type EventMultiplexer struct {
	mu          sync.RWMutex
	cfg         MultiplexerConfig
	subscribers map[string]*subscriberHandle
	ingested    int64
	dispatched  int64
	dropped     int64
}

// NewEventMultiplexer constructs an active non-blocking event multiplexer.
func NewEventMultiplexer(cfg MultiplexerConfig) *EventMultiplexer {
	if err := ValidateMultiplexerConfig(cfg); err != nil {
		cfg = DefaultMultiplexerConfig()
	}
	return &EventMultiplexer{
		cfg:         cfg,
		subscribers: make(map[string]*subscriberHandle),
	}
}

// Subscribe registers an event listener with optional filtering and bounded buffer.
func (m *EventMultiplexer) Subscribe(id string, filter EventFilter, bufSize int) (<-chan DockerEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.cfg.Enabled {
		return nil, errors.New("event multiplexer is disabled")
	}

	if id == "" {
		id = fmt.Sprintf("sub-%d", len(m.subscribers)+1)
	}

	if _, exists := m.subscribers[id]; exists {
		return nil, fmt.Errorf("subscriber ID '%s' already registered", id)
	}

	if len(m.subscribers) >= m.cfg.MaxSubscribers {
		return nil, fmt.Errorf("maximum subscribers limit (%d) reached", m.cfg.MaxSubscribers)
	}

	capacity := bufSize
	if capacity <= 0 {
		capacity = m.cfg.BufferSize
	}
	if capacity > 4096 {
		capacity = 4096
	}

	handle := &subscriberHandle{
		id:     id,
		filter: filter,
		ch:     make(chan DockerEvent, capacity),
	}

	m.subscribers[id] = handle
	return handle.ch, nil
}

// Unsubscribe removes and closes a subscriber's delivery channel.
func (m *EventMultiplexer) Unsubscribe(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	handle, exists := m.subscribers[id]
	if !exists {
		return false
	}

	if !handle.closed {
		handle.closed = true
		close(handle.ch)
	}
	delete(m.subscribers, id)
	return true
}

// Publish delivers an event to all matching subscribers without blocking.
func (m *EventMultiplexer) Publish(ev DockerEvent) {
	if !m.cfg.Enabled {
		return
	}

	atomic.AddInt64(&m.ingested, 1)

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, handle := range m.subscribers {
		if handle.closed {
			continue
		}

		if !handle.filter.Matches(ev) {
			continue
		}

		select {
		case handle.ch <- ev:
			atomic.AddInt64(&m.dispatched, 1)
		default:
			// Buffer is full: enforce backpressure policy
			m.handleBackpressure(handle, ev)
		}
	}
}

// handleBackpressure manages saturated subscriber buffers according to drop policy.
func (m *EventMultiplexer) handleBackpressure(handle *subscriberHandle, ev DockerEvent) {
	atomic.AddInt64(&m.dropped, 1)
	atomic.AddInt64(&handle.dropped, 1)

	switch m.cfg.DropPolicy {
	case DropOldest:
		// Drain the oldest event to make room for the fresh one
		select {
		case <-handle.ch:
		default:
		}

		// Retry inserting the new event
		select {
		case handle.ch <- ev:
			atomic.AddInt64(&m.dispatched, 1)
		default:
			// If still full, drop new
		}

	case DropNewest:
		// Drop the incoming event without altering buffered history
	}
}

// Stats returns aggregated multiplexer throughput and subscriber metrics.
func (m *EventMultiplexer) Stats() MultiplexerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	totalQueueDepth := 0
	for _, handle := range m.subscribers {
		totalQueueDepth += len(handle.ch)
	}

	return MultiplexerStats{
		ActiveSubscribers: len(m.subscribers),
		TotalIngested:     atomic.LoadInt64(&m.ingested),
		TotalDispatched:   atomic.LoadInt64(&m.dispatched),
		TotalDropped:      atomic.LoadInt64(&m.dropped),
		QueueDepth:        totalQueueDepth,
	}
}

// SubscriberStats returns per-subscriber drop count and queue length.
func (m *EventMultiplexer) SubscriberStats(id string) (queueDepth int, dropped int64, found bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	handle, exists := m.subscribers[id]
	if !exists {
		return 0, 0, false
	}
	return len(handle.ch), atomic.LoadInt64(&handle.dropped), true
}

// Config returns a copy of current multiplexer settings.
func (m *EventMultiplexer) Config() MultiplexerConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// UpdateConfig updates multiplexer settings at runtime.
func (m *EventMultiplexer) UpdateConfig(cfg MultiplexerConfig) error {
	if err := ValidateMultiplexerConfig(cfg); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
	return nil
}

// Close gracefully closes all active subscriber channels and terminates the multiplexer.
func (m *EventMultiplexer) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, handle := range m.subscribers {
		if !handle.closed {
			handle.closed = true
			close(handle.ch)
		}
		delete(m.subscribers, id)
	}
}
