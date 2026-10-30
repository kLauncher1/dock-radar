package raft

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kLauncher1/dock-radar/internal/healing"
)

var (
	ErrUnknownCommand = errors.New("unknown raft state machine command")
	ErrInvalidPayload = errors.New("invalid state machine payload")
)

// StateMachine defines the replicated state machine for the Raft consensus cluster.
type StateMachine struct {
	mu            sync.RWMutex
	healingPolicy healing.PolicyConfig
	blacklist     map[string]BlacklistEntry
	nodeStates    map[string]ClusterNodeState
	configKV      map[string]string
	appliedCount  uint64
}

// FSMSnapshot represents the full state machine snapshot payload for compaction and restore.
type FSMSnapshot struct {
	HealingPolicy healing.PolicyConfig        `json:"healing_policy"`
	Blacklist     map[string]BlacklistEntry   `json:"blacklist"`
	NodeStates    map[string]ClusterNodeState `json:"node_states"`
	ConfigKV      map[string]string           `json:"config_kv"`
	AppliedCount  uint64                      `json:"applied_count"`
	Timestamp     time.Time                   `json:"timestamp"`
}

// NewStateMachine constructs a newly initialized, thread-safe replicated state machine.
func NewStateMachine() *StateMachine {
	return &StateMachine{
		healingPolicy: healing.DefaultPolicyConfig(),
		blacklist:     make(map[string]BlacklistEntry),
		nodeStates:    make(map[string]ClusterNodeState),
		configKV:      make(map[string]string),
	}
}

// Apply executes a committed log entry against the state machine deterministically.
func (f *StateMachine) Apply(entry LogEntry) (*ApplyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.appliedCount++
	res := &ApplyResult{
		Success: true,
		Index:   entry.Index,
		Term:    entry.Term,
	}

	switch entry.Type {
	case CmdSetHealingPolicy:
		var pol healing.PolicyConfig
		if err := json.Unmarshal(entry.Data, &pol); err != nil {
			return nil, fmt.Errorf("%w: failed to parse healing policy: %v", ErrInvalidPayload, err)
		}
		if err := pol.Validate(); err != nil {
			return nil, fmt.Errorf("%w: healing policy failed validation: %v", ErrInvalidPayload, err)
		}
		f.healingPolicy = pol
		res.Message = "healing policy updated"
		res.Data = pol

	case CmdAddBlacklist:
		var bl BlacklistEntry
		if err := json.Unmarshal(entry.Data, &bl); err != nil {
			return nil, fmt.Errorf("%w: failed to parse blacklist entry: %v", ErrInvalidPayload, err)
		}
		bl.ContainerID = strings.TrimSpace(bl.ContainerID)
		if bl.ContainerID == "" {
			return nil, fmt.Errorf("%w: container_id cannot be empty", ErrInvalidPayload)
		}
		if bl.AddedAt.IsZero() {
			bl.AddedAt = entry.Timestamp
		}
		f.blacklist[bl.ContainerID] = bl
		res.Message = fmt.Sprintf("container %s added to blacklist", bl.ContainerID)
		res.Data = bl

	case CmdRemoveBlacklist:
		var target struct {
			ContainerID string `json:"container_id"`
		}
		if err := json.Unmarshal(entry.Data, &target); err != nil {
			// Fallback: try raw string
			target.ContainerID = strings.Trim(string(entry.Data), "\" \t\r\n")
		}
		target.ContainerID = strings.TrimSpace(target.ContainerID)
		if target.ContainerID == "" {
			return nil, fmt.Errorf("%w: container_id cannot be empty", ErrInvalidPayload)
		}
		delete(f.blacklist, target.ContainerID)
		res.Message = fmt.Sprintf("container %s removed from blacklist", target.ContainerID)
		res.Data = target.ContainerID

	case CmdUpdateNodeState:
		var ns ClusterNodeState
		if err := json.Unmarshal(entry.Data, &ns); err != nil {
			return nil, fmt.Errorf("%w: failed to parse cluster node state: %v", ErrInvalidPayload, err)
		}
		ns.NodeID = strings.TrimSpace(ns.NodeID)
		if err := ValidateNodeID(ns.NodeID); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
		}
		if ns.LastSeen.IsZero() {
			ns.LastSeen = entry.Timestamp
		}
		f.nodeStates[ns.NodeID] = ns
		res.Message = fmt.Sprintf("node %s state updated", ns.NodeID)
		res.Data = ns

	case CmdClusterConfig:
		var kv struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		if err := json.Unmarshal(entry.Data, &kv); err != nil {
			return nil, fmt.Errorf("%w: failed to parse cluster config key-value: %v", ErrInvalidPayload, err)
		}
		kv.Key = strings.TrimSpace(kv.Key)
		if kv.Key == "" {
			return nil, fmt.Errorf("%w: config key cannot be empty", ErrInvalidPayload)
		}
		f.configKV[kv.Key] = kv.Value
		res.Message = fmt.Sprintf("config %s set", kv.Key)
		res.Data = kv

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownCommand, entry.Type)
	}

	return res, nil
}

// GetHealingPolicy returns a thread-safe copy of the cluster-wide self-healing policy.
func (f *StateMachine) GetHealingPolicy() healing.PolicyConfig {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.healingPolicy
}

// GetBlacklist returns all active blacklist entries.
func (f *StateMachine) GetBlacklist() []BlacklistEntry {
	f.mu.RLock()
	defer f.mu.RUnlock()

	res := make([]BlacklistEntry, 0, len(f.blacklist))
	for _, entry := range f.blacklist {
		res = append(res, entry)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].ContainerID < res[j].ContainerID
	})
	return res
}

// IsBlacklisted returns true if the container identifier is currently quarantined in the blacklist.
func (f *StateMachine) IsBlacklisted(containerID string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	entry, found := f.blacklist[strings.TrimSpace(containerID)]
	if !found {
		return false
	}
	if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		return false
	}
	return true
}

// GetNodeStates returns all registered cluster node states.
func (f *StateMachine) GetNodeStates() []ClusterNodeState {
	f.mu.RLock()
	defer f.mu.RUnlock()

	res := make([]ClusterNodeState, 0, len(f.nodeStates))
	for _, st := range f.nodeStates {
		res = append(res, st)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].NodeID < res[j].NodeID
	})
	return res
}

// GetConfig retrieves a cluster-wide configuration value by key.
func (f *StateMachine) GetConfig(key string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	val, ok := f.configKV[key]
	return val, ok
}

// GetAllConfigs returns a clone of all cluster key-value parameters.
func (f *StateMachine) GetAllConfigs() map[string]string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	res := make(map[string]string, len(f.configKV))
	for k, v := range f.configKV {
		res[k] = v
	}
	return res
}

// AppliedCount returns the total number of applied log commands.
func (f *StateMachine) AppliedCount() uint64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.appliedCount
}

// Snapshot serializes the complete in-memory state for checkpointing.
func (f *StateMachine) Snapshot() ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	snap := FSMSnapshot{
		HealingPolicy: f.healingPolicy,
		Blacklist:     f.blacklist,
		NodeStates:    f.nodeStates,
		ConfigKV:      f.configKV,
		AppliedCount:  f.appliedCount,
		Timestamp:     time.Now().UTC(),
	}
	return json.Marshal(snap)
}

// Restore resets and reconstructs state machine contents from a snapshot payload.
func (f *StateMachine) Restore(data []byte) error {
	var snap FSMSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("failed to unmarshal FSM snapshot: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.healingPolicy = snap.HealingPolicy
	if snap.Blacklist != nil {
		f.blacklist = snap.Blacklist
	} else {
		f.blacklist = make(map[string]BlacklistEntry)
	}
	if snap.NodeStates != nil {
		f.nodeStates = snap.NodeStates
	} else {
		f.nodeStates = make(map[string]ClusterNodeState)
	}
	if snap.ConfigKV != nil {
		f.configKV = snap.ConfigKV
	} else {
		f.configKV = make(map[string]string)
	}
	f.appliedCount = snap.AppliedCount
	return nil
}
