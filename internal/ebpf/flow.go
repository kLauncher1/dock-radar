package ebpf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FlowTracker maintains an in-memory, thread-safe repository of active and historical socket flows.
type FlowTracker struct {
	mu           sync.RWMutex
	flows        map[string]*SocketFlow
	maxFlows     int
	totalTracked uint64
	bytesIngress uint64
	bytesEgress  uint64
}

// NewFlowTracker constructs a flow repository bounded by maxFlows.
func NewFlowTracker(maxFlows int) *FlowTracker {
	if maxFlows <= 0 {
		maxFlows = 2000
	}
	return &FlowTracker{
		flows:    make(map[string]*SocketFlow),
		maxFlows: maxFlows,
	}
}

// GenerateFlowID creates a deterministic hash identifier for a connection tuple.
func GenerateFlowID(containerID, proto, localAddr, remoteAddr string) string {
	raw := fmt.Sprintf("%s:%s:%s:%s", containerID, proto, localAddr, remoteAddr)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:8])
}

// RecordFlow upserts a socket flow, calculating delta throughput and tracking state changes.
func (ft *FlowTracker) RecordFlow(flow SocketFlow) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	if flow.ID == "" {
		flow.ID = GenerateFlowID(flow.ContainerID, flow.Protocol, flow.LocalAddr, flow.RemoteAddr)
	}

	now := time.Now().UTC()
	if flow.LastSeen.IsZero() {
		flow.LastSeen = now
	}

	existing, found := ft.flows[flow.ID]
	if found {
		// Calculate incremental deltas for monotonic counters
		if flow.BytesRecv > existing.BytesRecv {
			atomic.AddUint64(&ft.bytesIngress, flow.BytesRecv-existing.BytesRecv)
		}
		if flow.BytesSent > existing.BytesSent {
			atomic.AddUint64(&ft.bytesEgress, flow.BytesSent-existing.BytesSent)
		}

		// Update mutable fields
		existing.State = flow.State
		existing.BytesSent = flow.BytesSent
		existing.BytesRecv = flow.BytesRecv
		existing.PacketsSent = flow.PacketsSent
		existing.PacketsRecv = flow.PacketsRecv
		existing.Retransmits = flow.Retransmits
		existing.RTTMillis = flow.RTTMillis
		existing.PID = flow.PID
		existing.Comm = flow.Comm
		existing.LastSeen = flow.LastSeen
		if flow.ContainerName != "" {
			existing.ContainerName = flow.ContainerName
		}
		return
	}

	// Capacity enforcement via LRU eviction
	if len(ft.flows) >= ft.maxFlows {
		ft.evictOldestLocked(len(ft.flows) - ft.maxFlows + 1)
	}

	if flow.FirstSeen.IsZero() {
		flow.FirstSeen = now
	}

	atomic.AddUint64(&ft.totalTracked, 1)
	atomic.AddUint64(&ft.bytesIngress, flow.BytesRecv)
	atomic.AddUint64(&ft.bytesEgress, flow.BytesSent)

	flowCopy := flow
	ft.flows[flow.ID] = &flowCopy
}

// evictOldestLocked removes the oldest flows when maximum capacity is breached.
func (ft *FlowTracker) evictOldestLocked(count int) {
	if count <= 0 || len(ft.flows) == 0 {
		return
	}

	type flowAge struct {
		id       string
		lastSeen time.Time
	}

	candidates := make([]flowAge, 0, len(ft.flows))
	for id, f := range ft.flows {
		candidates = append(candidates, flowAge{id: id, lastSeen: f.LastSeen})
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].lastSeen.Before(candidates[j].lastSeen)
	})

	toDelete := count
	if toDelete > len(candidates) {
		toDelete = len(candidates)
	}

	for i := 0; i < toDelete; i++ {
		delete(ft.flows, candidates[i].id)
	}
}

// PruneStale removes closed or inactive flows older than maxAge.
func (ft *FlowTracker) PruneStale(maxAge time.Duration) int {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	cutoff := time.Now().UTC().Add(-maxAge)
	pruned := 0

	for id, flow := range ft.flows {
		// Preserve persistent LISTEN sockets unless extremely stale
		if flow.State == "LISTEN" && flow.LastSeen.After(cutoff.Add(-5*maxAge)) {
			continue
		}
		if flow.LastSeen.Before(cutoff) {
			delete(ft.flows, id)
			pruned++
		}
	}
	return pruned
}

// List returns flows matching the provided filter criteria, sorted by LastSeen descending.
func (ft *FlowTracker) List(filter FlowFilter) []SocketFlow {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	matched := make([]SocketFlow, 0, len(ft.flows))
	for _, f := range ft.flows {
		if filter.ContainerID != "" && f.ContainerID != filter.ContainerID {
			continue
		}
		if filter.State != "" && !strings.EqualFold(f.State, filter.State) {
			continue
		}
		if filter.Protocol != "" && !strings.EqualFold(f.Protocol, filter.Protocol) {
			continue
		}
		matched = append(matched, *f)
	}

	// Sort most recent first
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].LastSeen.After(matched[j].LastSeen)
	})

	if filter.Limit > 0 && len(matched) > filter.Limit {
		matched = matched[:filter.Limit]
	}

	return matched
}

// Get retrieves a specific flow by its unique identifier.
func (ft *FlowTracker) Get(id string) (SocketFlow, bool) {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	flow, found := ft.flows[id]
	if !found {
		return SocketFlow{}, false
	}
	return *flow, true
}

// Stats returns aggregate metrics on tracked network flows.
func (ft *FlowTracker) Stats() (active int, total uint64, ingress uint64, egress uint64) {
	ft.mu.RLock()
	active = len(ft.flows)
	ft.mu.RUnlock()

	total = atomic.LoadUint64(&ft.totalTracked)
	ingress = atomic.LoadUint64(&ft.bytesIngress)
	egress = atomic.LoadUint64(&ft.bytesEgress)
	return
}

// Reset clears all recorded flows and resets throughput counters.
func (ft *FlowTracker) Reset() {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	ft.flows = make(map[string]*SocketFlow)
	atomic.StoreUint64(&ft.totalTracked, 0)
	atomic.StoreUint64(&ft.bytesIngress, 0)
	atomic.StoreUint64(&ft.bytesEgress, 0)
}
