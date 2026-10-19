package firewall

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// NetworkIsolator manages container zero-trust isolation policies and quarantine statuses.
type NetworkIsolator struct {
	mu          sync.RWMutex
	states      map[string]*ContainerIsolationState
	globalZero  bool
}

// NewNetworkIsolator instantiates an isolator with optional global zero-trust enforcement.
func NewNetworkIsolator(globalZeroTrust bool) *NetworkIsolator {
	return &NetworkIsolator{
		states:     make(map[string]*ContainerIsolationState),
		globalZero: globalZeroTrust,
	}
}

// SetIsolation sets the containment policy for a specific container.
func (ni *NetworkIsolator) SetIsolation(containerID, containerName string, level IsolationLevel, reason string, allowedPeers []string, egressLimit, ingressLimit uint64) ContainerIsolationState {
	ni.mu.Lock()
	defer ni.mu.Unlock()

	cleanedPeers := make([]string, 0, len(allowedPeers))
	for _, p := range allowedPeers {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			cleanedPeers = append(cleanedPeers, trimmed)
		}
	}

	st, exists := ni.states[containerID]
	if !exists {
		st = &ContainerIsolationState{
			ContainerID:   containerID,
			ContainerName: containerName,
		}
		ni.states[containerID] = st
	}

	st.ContainerName = containerName
	st.IsolationLevel = level
	st.Reason = reason
	st.IsolatedAt = time.Now().UTC()
	st.AllowedPeers = cleanedPeers
	st.EgressBandwidthLimitBPS = egressLimit
	st.IngressBandwidthLimitBPS = ingressLimit
	st.IsQuarantined = (level == IsolationFullQuarantine)

	return *st
}

// Quarantine puts a container into complete isolation immediately.
func (ni *NetworkIsolator) Quarantine(containerID, containerName, reason string) ContainerIsolationState {
	return ni.SetIsolation(containerID, containerName, IsolationFullQuarantine, reason, nil, 0, 0)
}

// RemoveIsolation releases a container from custom isolation back to normal/global baseline.
func (ni *NetworkIsolator) RemoveIsolation(containerID string) bool {
	ni.mu.Lock()
	defer ni.mu.Unlock()

	if _, exists := ni.states[containerID]; !exists {
		return false
	}
	delete(ni.states, containerID)
	return true
}

// GetIsolation retrieves current isolation posture for a container.
func (ni *NetworkIsolator) GetIsolation(containerID string) (ContainerIsolationState, bool) {
	ni.mu.RLock()
	defer ni.mu.RUnlock()

	st, exists := ni.states[containerID]
	if !exists {
		return ContainerIsolationState{}, false
	}
	res := *st
	res.DroppedPackets = atomic.LoadUint64(&st.DroppedPackets)
	res.DroppedBytes = atomic.LoadUint64(&st.DroppedBytes)
	res.ThrottledEvents = atomic.LoadUint64(&st.ThrottledEvents)
	return res, true
}

// ListIsolations returns all active container isolation records.
func (ni *NetworkIsolator) ListIsolations() []ContainerIsolationState {
	ni.mu.RLock()
	defer ni.mu.RUnlock()

	res := make([]ContainerIsolationState, 0, len(ni.states))
	for _, st := range ni.states {
		copyState := *st
		copyState.DroppedPackets = atomic.LoadUint64(&st.DroppedPackets)
		copyState.DroppedBytes = atomic.LoadUint64(&st.DroppedBytes)
		copyState.ThrottledEvents = atomic.LoadUint64(&st.ThrottledEvents)
		res = append(res, copyState)
	}
	return res
}

// SetGlobalZeroTrust enables or disables default zero-trust containment for inter-container traffic.
func (ni *NetworkIsolator) SetGlobalZeroTrust(enabled bool) {
	ni.mu.Lock()
	defer ni.mu.Unlock()
	ni.globalZero = enabled
}

// IsGlobalZeroTrust returns whether global zero-trust is active.
func (ni *NetworkIsolator) IsGlobalZeroTrust() bool {
	ni.mu.RLock()
	defer ni.mu.RUnlock()
	return ni.globalZero
}

// CheckTraffic evaluates zero-trust and quarantine boundaries between endpoints.
func (ni *NetworkIsolator) CheckTraffic(srcContainerID, dstContainerID string, isInterContainer bool) (PolicyAction, string) {
	ni.mu.RLock()
	defer ni.mu.RUnlock()

	// 1. Check Source Quarantine
	if srcState, ok := ni.states[srcContainerID]; ok {
		if srcState.IsolationLevel == IsolationFullQuarantine {
			atomic.AddUint64(&srcState.DroppedPackets, 1)
			return ActionDrop, fmt.Sprintf("Source container %s is in FULL QUARANTINE: %s", srcContainerID, srcState.Reason)
		}
	}

	// 2. Check Destination Quarantine
	if dstContainerID != "" {
		if dstState, ok := ni.states[dstContainerID]; ok {
			if dstState.IsolationLevel == IsolationFullQuarantine {
				atomic.AddUint64(&dstState.DroppedPackets, 1)
				return ActionDrop, fmt.Sprintf("Destination container %s is in FULL QUARANTINE: %s", dstContainerID, dstState.Reason)
			}
		}
	}

	// 3. If this is not inter-container traffic (e.g. to external internet), Partial isolation allows it
	if !isInterContainer {
		return ActionAllow, "External traffic permitted"
	}

	// 4. Inter-container traffic evaluation
	if srcState, ok := ni.states[srcContainerID]; ok {
		switch srcState.IsolationLevel {
		case IsolationPartial:
			atomic.AddUint64(&srcState.DroppedPackets, 1)
			return ActionDrop, fmt.Sprintf("Container %s is in PARTIAL isolation (inter-container blocked)", srcContainerID)

		case IsolationStrictZero:
			if !isPeerWhitelisted(srcState.AllowedPeers, dstContainerID) {
				atomic.AddUint64(&srcState.DroppedPackets, 1)
				return ActionDrop, fmt.Sprintf("Zero-trust violation: destination %s not in allowed peers list of container %s", dstContainerID, srcContainerID)
			}
			return ActionAllow, "Whitelisted inter-container peer flow"
		}
	}

	// 5. Check if destination requires strict isolation
	if dstContainerID != "" {
		if dstState, ok := ni.states[dstContainerID]; ok {
			switch dstState.IsolationLevel {
			case IsolationPartial:
				atomic.AddUint64(&dstState.DroppedPackets, 1)
				return ActionDrop, fmt.Sprintf("Destination %s is in PARTIAL isolation (inter-container ingress blocked)", dstContainerID)

			case IsolationStrictZero:
				if !isPeerWhitelisted(dstState.AllowedPeers, srcContainerID) {
					atomic.AddUint64(&dstState.DroppedPackets, 1)
					return ActionDrop, fmt.Sprintf("Zero-trust ingress violation: source %s not in allowed peers list of destination %s", srcContainerID, dstContainerID)
				}
				return ActionAllow, "Whitelisted inter-container peer flow"
			}
		}
	}

	// 6. Global Zero-Trust Baseline
	if ni.globalZero {
		return ActionDrop, "Global zero-trust network policy active: inter-container traffic blocked by default"
	}

	return ActionAllow, "Allowed by network policy"
}

// RecordDroppedStats records dropped packet and byte volume for a container.
func (ni *NetworkIsolator) RecordDroppedStats(containerID string, packets, bytes uint64) {
	ni.mu.RLock()
	defer ni.mu.RUnlock()

	if st, ok := ni.states[containerID]; ok {
		atomic.AddUint64(&st.DroppedPackets, packets)
		atomic.AddUint64(&st.DroppedBytes, bytes)
	}
}

func isPeerWhitelisted(allowed []string, target string) bool {
	for _, p := range allowed {
		if p == "*" || p == target || strings.HasPrefix(target, p) || strings.HasPrefix(p, target) {
			return true
		}
	}
	return false
}
