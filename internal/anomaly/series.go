package anomaly

import (
	"sync"
	"time"
)

// MetricSample represents a single point-in-time resource measurement.
type MetricSample struct {
	Timestamp   time.Time `json:"timestamp"`
	MemoryBytes uint64    `json:"memory_bytes"`
	MemoryLimit uint64    `json:"memory_limit"`
	CPUPercent  float64   `json:"cpu_percent"`
}

// ContainerSeries maintains a bounded rolling window of metrics for a container.
type ContainerSeries struct {
	mu         sync.RWMutex
	samples    []MetricSample
	capacity   int
	head       int
	count      int
	lastSeen   time.Time
	name       string
	id         string
}

// NewContainerSeries creates a bounded circular metrics buffer.
func NewContainerSeries(id, name string, capacity int) *ContainerSeries {
	if capacity <= 0 {
		capacity = 60
	}
	return &ContainerSeries{
		id:       id,
		name:     name,
		capacity: capacity,
		samples:  make([]MetricSample, capacity),
		lastSeen: time.Now().UTC(),
	}
}

// Add appends a new metric sample to the circular buffer.
func (cs *ContainerSeries) Add(sample MetricSample) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if sample.Timestamp.IsZero() {
		sample.Timestamp = time.Now().UTC()
	}

	cs.samples[cs.head] = sample
	cs.head = (cs.head + 1) % cs.capacity
	if cs.count < cs.capacity {
		cs.count++
	}
	cs.lastSeen = sample.Timestamp
}

// Samples returns a chronological slice of recorded samples.
func (cs *ContainerSeries) Samples() []MetricSample {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	result := make([]MetricSample, cs.count)
	if cs.count == 0 {
		return result
	}

	start := (cs.head - cs.count + cs.capacity) % cs.capacity
	for i := 0; i < cs.count; i++ {
		idx := (start + i) % cs.capacity
		result[i] = cs.samples[idx]
	}
	return result
}

// Latest returns the most recent sample recorded.
func (cs *ContainerSeries) Latest() (MetricSample, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if cs.count == 0 {
		return MetricSample{}, false
	}
	lastIdx := (cs.head - 1 + cs.capacity) % cs.capacity
	return cs.samples[lastIdx], true
}

// Count returns the number of samples currently stored.
func (cs *ContainerSeries) Count() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.count
}

// TrackerStore manages time-series tracking across all containers in a thread-safe manner.
type TrackerStore struct {
	mu           sync.RWMutex
	series       map[string]*ContainerSeries
	maxContainers int
	sampleCap    int
}

// NewTrackerStore initializes the container metric tracking store.
func NewTrackerStore(maxContainers, sampleCap int) *TrackerStore {
	if maxContainers <= 0 {
		maxContainers = 500
	}
	if sampleCap <= 0 {
		sampleCap = 60
	}
	return &TrackerStore{
		series:        make(map[string]*ContainerSeries),
		maxContainers: maxContainers,
		sampleCap:     sampleCap,
	}
}

// RecordMetric records a new metric sample for the target container.
func (ts *TrackerStore) RecordMetric(id, name string, sample MetricSample) {
	ts.mu.Lock()
	s, exists := ts.series[id]
	if !exists {
		if len(ts.series) >= ts.maxContainers {
			ts.evictStaleLocked()
		}
		s = NewContainerSeries(id, name, ts.sampleCap)
		ts.series[id] = s
	} else if name != "" && s.name != name {
		s.name = name
	}
	ts.mu.Unlock()

	s.Add(sample)
}

// GetSeries returns the metric series for a container if available.
func (ts *TrackerStore) GetSeries(id string) (*ContainerSeries, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	s, exists := ts.series[id]
	return s, exists
}

// AllSeries returns a snapshot of all active series.
func (ts *TrackerStore) AllSeries() map[string]*ContainerSeries {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	out := make(map[string]*ContainerSeries, len(ts.series))
	for k, v := range ts.series {
		out[k] = v
	}
	return out
}

// PruneStale removes series that have not received samples within the retention duration.
func (ts *TrackerStore) PruneStale(maxAge time.Duration) int {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	threshold := time.Now().UTC().Add(-maxAge)
	pruned := 0
	for id, s := range ts.series {
		s.mu.RLock()
		lastSeen := s.lastSeen
		s.mu.RUnlock()

		if lastSeen.Before(threshold) {
			delete(ts.series, id)
			pruned++
		}
	}
	return pruned
}

// evictStaleLocked removes the oldest inactive container to satisfy maximum memory bounds.
func (ts *TrackerStore) evictStaleLocked() {
	var oldestID string
	var oldestTime time.Time

	for id, s := range ts.series {
		s.mu.RLock()
		seen := s.lastSeen
		s.mu.RUnlock()

		if oldestID == "" || seen.Before(oldestTime) {
			oldestID = id
			oldestTime = seen
		}
	}

	if oldestID != "" {
		delete(ts.series, oldestID)
	}
}

// Len returns the number of actively tracked containers.
func (ts *TrackerStore) Len() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.series)
}
