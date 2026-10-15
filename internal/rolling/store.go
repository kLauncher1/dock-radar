package rolling

import (
	"sync"
)

// Store provides thread-safe in-memory caching and historical logging of rolling operations.
type Store struct {
	mu         sync.RWMutex
	capacity   int
	operations []*RollingOperation
	byID       map[string]*RollingOperation
}

// NewStore initializes a rolling operation store with bounded memory capacity.
func NewStore(capacity int) *Store {
	if capacity <= 0 {
		capacity = 200
	}
	return &Store{
		capacity:   capacity,
		operations: make([]*RollingOperation, 0, capacity),
		byID:       make(map[string]*RollingOperation),
	}
}

// Save inserts or updates a rolling restart operation record in the store.
func (s *Store) Save(op *RollingOperation) {
	if op == nil || op.ID == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// If already tracked, update in-place
	if existing, found := s.byID[op.ID]; found {
		*existing = *op
		return
	}

	// Evict oldest if capacity exceeded
	if len(s.operations) >= s.capacity {
		evicted := s.operations[0]
		delete(s.byID, evicted.ID)
		s.operations = s.operations[1:]
	}

	cloned := *op
	s.operations = append(s.operations, &cloned)
	s.byID[op.ID] = &cloned
}

// Get retrieves a specific rolling operation by its unique ID.
func (s *Store) Get(id string) (*RollingOperation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	op, found := s.byID[id]
	if !found {
		return nil, false
	}
	cloned := *op
	return &cloned, true
}

// List returns recent rolling operations in reverse chronological order (newest first).
func (s *Store) List(limit int) []*RollingOperation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.operations)
	if limit <= 0 || limit > total {
		limit = total
	}

	result := make([]*RollingOperation, 0, limit)
	for i := total - 1; i >= 0 && len(result) < limit; i-- {
		cloned := *s.operations[i]
		result = append(result, &cloned)
	}
	return result
}

// Active returns all operations currently in pending, draining, restarting, or probing states.
func (s *Store) Active() []*RollingOperation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var active []*RollingOperation
	for _, op := range s.operations {
		if op.Status == StatusPending || op.Status == StatusDraining || op.Status == StatusRestarting || op.Status == StatusProbing {
			cloned := *op
			active = append(active, &cloned)
		}
	}
	return active
}

// Count returns the total number of recorded operations in store.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.operations)
}
