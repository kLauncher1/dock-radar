package raft

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDefaultRaftConfig_Validate(t *testing.T) {
	cfg := DefaultRaftConfig()
	if err := ValidateRaftConfig(cfg); err != nil {
		t.Fatalf("DefaultRaftConfig failed validation: %v", err)
	}
	if !cfg.Enabled {
		t.Errorf("expected Enabled=true")
	}
	if cfg.NodeID == "" {
		t.Errorf("expected non-empty NodeID")
	}
}

func TestValidateNodeID(t *testing.T) {
	validIDs := []string{"node-1", "node_coordinator.east", "cluster-mgr-01", "A1"}
	for _, id := range validIDs {
		if err := ValidateNodeID(id); err != nil {
			t.Errorf("expected valid node ID for %q, got error: %v", id, err)
		}
	}

	invalidIDs := []string{"", "   ", "node/slash", "node$bad", "!node", "-invalid-start"}
	for _, id := range invalidIDs {
		if err := ValidateNodeID(id); err == nil {
			t.Errorf("expected error for invalid node ID %q, got nil", id)
		}
	}
}

func TestValidateRaftConfig_Errors(t *testing.T) {
	cfg := DefaultRaftConfig()
	cfg.HeartbeatInterval = 5 * time.Millisecond // too low (below 10ms)
	if err := ValidateRaftConfig(cfg); err == nil {
		t.Errorf("expected error for heartbeat interval < 10ms, got nil")
	}

	cfg = DefaultRaftConfig()
	cfg.ElectionTimeoutMin = 500 * time.Millisecond
	cfg.ElectionTimeoutMax = 300 * time.Millisecond // max < min
	if err := ValidateRaftConfig(cfg); err == nil {
		t.Errorf("expected error for max timeout < min timeout, got nil")
	}

	cfg = DefaultRaftConfig()
	cfg.Peers = []string{"://invalid-url"}
	if err := ValidateRaftConfig(cfg); err == nil {
		t.Errorf("expected error for malformed peer URL, got nil")
	}
}

func TestLogEntry_Serialization(t *testing.T) {
	entry := LogEntry{
		Index:     42,
		Term:      3,
		Type:      CmdAddBlacklist,
		Data:      []byte(`{"container_id":"c123","reason":"OOM loop"}`),
		Timestamp: time.Now().UTC().Truncate(time.Second),
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal LogEntry: %v", err)
	}

	var decoded LogEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal LogEntry: %v", err)
	}

	if decoded.Index != entry.Index || decoded.Term != entry.Term || decoded.Type != entry.Type {
		t.Errorf("decoded LogEntry mismatch: got %+v, want %+v", decoded, entry)
	}
	if string(decoded.Data) != string(entry.Data) {
		t.Errorf("decoded Data mismatch: got %s, want %s", string(decoded.Data), string(entry.Data))
	}
}
