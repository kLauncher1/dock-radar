package raft

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// RaftState represents the operational role of a node in the Raft consensus group.
type RaftState string

const (
	StateFollower  RaftState = "follower"
	StateCandidate RaftState = "candidate"
	StateLeader    RaftState = "leader"
)

// CommandType defines the type of state mutation replicated across the cluster.
type CommandType string

const (
	CmdSetHealingPolicy   CommandType = "set_healing_policy"
	CmdAddBlacklist       CommandType = "add_blacklist"
	CmdRemoveBlacklist    CommandType = "remove_blacklist"
	CmdUpdateNodeState    CommandType = "update_node_state"
	CmdClusterConfig      CommandType = "cluster_config"
)

var (
	ErrNotLeader       = errors.New("node is not the cluster leader")
	ErrInvalidConfig   = errors.New("invalid raft configuration")
	ErrQuorumNotMet    = errors.New("cluster quorum cannot be satisfied")
	ErrLogIndexOutOfBound = errors.New("log index out of bounds")

	nodeIDRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
)

// LogEntry encapsulates a single replicated state machine command in the Raft log.
type LogEntry struct {
	Index     uint64      `json:"index"`
	Term      uint64      `json:"term"`
	Type      CommandType `json:"type"`
	Data      []byte      `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// RequestVoteArgs contains arguments for the RequestVote RPC.
type RequestVoteArgs struct {
	Term         uint64 `json:"term"`
	CandidateID  string `json:"candidate_id"`
	LastLogIndex uint64 `json:"last_log_index"`
	LastLogTerm  uint64 `json:"last_log_term"`
}

// RequestVoteReply contains the reply from a RequestVote RPC.
type RequestVoteReply struct {
	Term        uint64 `json:"term"`
	VoteGranted bool   `json:"vote_granted"`
	Reason      string `json:"reason,omitempty"`
}

// AppendEntriesArgs contains arguments for the AppendEntries RPC (replicate or heartbeat).
type AppendEntriesArgs struct {
	Term         uint64     `json:"term"`
	LeaderID     string     `json:"leader_id"`
	PrevLogIndex uint64     `json:"prev_log_index"`
	PrevLogTerm  uint64     `json:"prev_log_term"`
	Entries      []LogEntry `json:"entries,omitempty"`
	LeaderCommit uint64     `json:"leader_commit"`
}

// AppendEntriesReply contains the reply from an AppendEntries RPC.
type AppendEntriesReply struct {
	Term       uint64 `json:"term"`
	Success    bool   `json:"success"`
	MatchIndex uint64 `json:"match_index"`
	Reason     string `json:"reason,omitempty"`
}

// BlacklistEntry defines a container quarantine or isolation record replicated across the mesh.
type BlacklistEntry struct {
	ContainerID string    `json:"container_id"`
	Reason      string    `json:"reason"`
	AddedAt     time.Time `json:"added_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	AddedBy     string    `json:"added_by"`
}

// ClusterNodeState defines cluster coordinator metadata replicated across the state machine.
type ClusterNodeState struct {
	NodeID    string    `json:"node_id"`
	Address   string    `json:"address"`
	Status    string    `json:"status"`
	Role      string    `json:"role"`
	LastSeen  time.Time `json:"last_seen"`
	Version   string    `json:"version"`
}

// ApplyResult represents the outcome of an applied state machine command.
type ApplyResult struct {
	Success bool   `json:"success"`
	Index   uint64 `json:"index"`
	Term    uint64 `json:"term"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

// RaftConfig configures the embedded consensus engine.
type RaftConfig struct {
	Enabled             bool          `json:"enabled"`
	NodeID              string        `json:"node_id"`
	BindAddr            string        `json:"bind_addr"`
	Peers               []string      `json:"peers"`
	HeartbeatInterval   time.Duration `json:"heartbeat_interval"`
	ElectionTimeoutMin  time.Duration `json:"election_timeout_min"`
	ElectionTimeoutMax  time.Duration `json:"election_timeout_max"`
	DataDir             string        `json:"data_dir"`
	MaxLogEntries       int           `json:"max_log_entries"`
	SnapshotThreshold   int           `json:"snapshot_threshold"`
}

// DefaultRaftConfig supplies production-grade baseline settings.
func DefaultRaftConfig() RaftConfig {
	return RaftConfig{
		Enabled:            true,
		NodeID:             "node-1",
		BindAddr:           "127.0.0.1:9080",
		Peers:              make([]string, 0),
		HeartbeatInterval:  200 * time.Millisecond,
		ElectionTimeoutMin: 800 * time.Millisecond,
		ElectionTimeoutMax: 1500 * time.Millisecond,
		DataDir:            "data/raft",
		MaxLogEntries:      10000,
		SnapshotThreshold:  1000,
	}
}

// ValidateNodeID ensures the node identifier is bounded and conforms to safe patterns.
func ValidateNodeID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("node ID cannot be empty")
	}
	if !nodeIDRegex.MatchString(id) {
		return fmt.Errorf("invalid node ID %q: must be 1-64 alphanumeric characters, underscores, dashes, or dots", id)
	}
	return nil
}

// ValidateRaftConfig performs validation checks on configuration parameters.
func ValidateRaftConfig(cfg RaftConfig) error {
	if err := ValidateNodeID(cfg.NodeID); err != nil {
		return err
	}
	if cfg.HeartbeatInterval < 10*time.Millisecond || cfg.HeartbeatInterval > 10*time.Second {
		return fmt.Errorf("%w: heartbeat interval must be between 10ms and 10s, got %v", ErrInvalidConfig, cfg.HeartbeatInterval)
	}
	if cfg.ElectionTimeoutMin < 20*time.Millisecond || cfg.ElectionTimeoutMin > 30*time.Second {
		return fmt.Errorf("%w: election timeout min must be between 20ms and 30s, got %v", ErrInvalidConfig, cfg.ElectionTimeoutMin)
	}
	if cfg.ElectionTimeoutMax <= cfg.ElectionTimeoutMin {
		return fmt.Errorf("%w: election timeout max (%v) must exceed min (%v)", ErrInvalidConfig, cfg.ElectionTimeoutMax, cfg.ElectionTimeoutMin)
	}
	for _, peer := range cfg.Peers {
		peer = strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		var parsedURL *url.URL
		var parseErr error
		if strings.HasPrefix(peer, "http://") || strings.HasPrefix(peer, "https://") {
			parsedURL, parseErr = url.Parse(peer)
		} else {
			if strings.Contains(peer, "://") {
				return fmt.Errorf("%w: invalid peer URL scheme %q", ErrInvalidConfig, peer)
			}
			parsedURL, parseErr = url.Parse("http://" + peer)
		}
		if parseErr != nil || parsedURL == nil || parsedURL.Host == "" {
			return fmt.Errorf("%w: invalid peer address %q", ErrInvalidConfig, peer)
		}
	}
	return nil
}

// RaftStatus encapsulates real-time consensus telemetry for metrics and API inspection.
type RaftStatus struct {
	NodeID               string    `json:"node_id"`
	State                string    `json:"state"`
	Term                 uint64    `json:"term"`
	LeaderID             string    `json:"leader_id"`
	CommitIndex          uint64    `json:"commit_index"`
	LastApplied          uint64    `json:"last_applied"`
	LastLogIndex         uint64    `json:"last_log_index"`
	LastLogTerm          uint64    `json:"last_log_term"`
	Peers                []string  `json:"peers"`
	PeerCount            int       `json:"peer_count"`
	QuorumSize           int       `json:"quorum_size"`
	IsLeader             bool      `json:"is_leader"`
	LogEntriesCount      int       `json:"log_entries_count"`
	AppliedCommandsCount uint64    `json:"applied_commands_count"`
	UptimeSeconds        uint64    `json:"uptime_seconds"`
}

// MarshalJSON provides safe serialization of LogEntry.
func (e LogEntry) String() string {
	b, _ := json.Marshal(e)
	return string(b)
}
