package raft

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/healing"
)

func TestStateMachine_ApplyHealingPolicy(t *testing.T) {
	fsm := NewStateMachine()

	pol := healing.DefaultPolicyConfig()
	pol.MaxAttempts = 10
	pol.BaseBackoffSec = 5
	pol.ExcludedContainers = []string{"core-db", "redis"}

	data, err := json.Marshal(pol)
	if err != nil {
		t.Fatalf("failed to marshal policy: %v", err)
	}

	entry := LogEntry{
		Index:     1,
		Term:      1,
		Type:      CmdSetHealingPolicy,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}

	res, err := fsm.Apply(entry)
	if err != nil {
		t.Fatalf("fsm.Apply failed: %v", err)
	}
	if !res.Success {
		t.Errorf("expected res.Success=true")
	}

	gotPol := fsm.GetHealingPolicy()
	if gotPol.MaxAttempts != 10 || gotPol.BaseBackoffSec != 5 {
		t.Errorf("healing policy did not update properly: %+v", gotPol)
	}
	if len(gotPol.ExcludedContainers) != 2 {
		t.Errorf("expected 2 excluded containers, got %d", len(gotPol.ExcludedContainers))
	}
}

func TestStateMachine_ApplyBlacklist(t *testing.T) {
	fsm := NewStateMachine()

	bl := BlacklistEntry{
		ContainerID: "app-worker-1",
		Reason:      "repeated out of memory failure",
		AddedAt:     time.Now().UTC(),
		AddedBy:     "node-leader",
	}
	data, _ := json.Marshal(bl)

	entry := LogEntry{
		Index:     1,
		Term:      1,
		Type:      CmdAddBlacklist,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}

	if _, err := fsm.Apply(entry); err != nil {
		t.Fatalf("failed to apply add blacklist: %v", err)
	}

	if !fsm.IsBlacklisted("app-worker-1") {
		t.Errorf("expected app-worker-1 to be blacklisted")
	}
	if fsm.IsBlacklisted("random-container") {
		t.Errorf("unexpected blacklist hit for random container")
	}

	list := fsm.GetBlacklist()
	if len(list) != 1 || list[0].ContainerID != "app-worker-1" {
		t.Errorf("blacklist list mismatch: %+v", list)
	}

	// Remove from blacklist
	removeEntry := LogEntry{
		Index:     2,
		Term:      1,
		Type:      CmdRemoveBlacklist,
		Data:      []byte(`{"container_id":"app-worker-1"}`),
		Timestamp: time.Now().UTC(),
	}
	if _, err := fsm.Apply(removeEntry); err != nil {
		t.Fatalf("failed to apply remove blacklist: %v", err)
	}

	if fsm.IsBlacklisted("app-worker-1") {
		t.Errorf("expected app-worker-1 to be un-blacklisted")
	}
}

func TestStateMachine_ApplyNodeStates(t *testing.T) {
	fsm := NewStateMachine()

	node := ClusterNodeState{
		NodeID:   "node-east-01",
		Address:  "http://10.0.1.5:9080",
		Status:   "online",
		Role:     "coordinator",
		LastSeen: time.Now().UTC(),
		Version:  "2.6.0",
	}
	data, _ := json.Marshal(node)

	entry := LogEntry{
		Index:     1,
		Term:      1,
		Type:      CmdUpdateNodeState,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}

	if _, err := fsm.Apply(entry); err != nil {
		t.Fatalf("failed to apply update node state: %v", err)
	}

	states := fsm.GetNodeStates()
	if len(states) != 1 || states[0].NodeID != "node-east-01" {
		t.Errorf("unexpected node states: %+v", states)
	}
}

func TestStateMachine_ApplyClusterConfig(t *testing.T) {
	fsm := NewStateMachine()

	entry := LogEntry{
		Index:     1,
		Term:      1,
		Type:      CmdClusterConfig,
		Data:      []byte(`{"key":"drain_timeout_sec","value":"45"}`),
		Timestamp: time.Now().UTC(),
	}

	if _, err := fsm.Apply(entry); err != nil {
		t.Fatalf("failed to apply cluster config: %v", err)
	}

	val, found := fsm.GetConfig("drain_timeout_sec")
	if !found || val != "45" {
		t.Errorf("expected config drain_timeout_sec=45, got %s (found: %v)", val, found)
	}

	all := fsm.GetAllConfigs()
	if len(all) != 1 || all["drain_timeout_sec"] != "45" {
		t.Errorf("unexpected all configs: %+v", all)
	}
}

func TestStateMachine_SnapshotAndRestore(t *testing.T) {
	fsm := NewStateMachine()

	_, _ = fsm.Apply(LogEntry{
		Index: 1, Term: 1, Type: CmdAddBlacklist,
		Data: []byte(`{"container_id":"bad-1","reason":"compromised"}`),
	})
	_, _ = fsm.Apply(LogEntry{
		Index: 2, Term: 1, Type: CmdClusterConfig,
		Data: []byte(`{"key":"cluster_zone","value":"us-east"}`),
	})

	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}

	fsm2 := NewStateMachine()
	if err := fsm2.Restore(snap); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	if !fsm2.IsBlacklisted("bad-1") {
		t.Errorf("restored fsm does not have bad-1 in blacklist")
	}
	if val, ok := fsm2.GetConfig("cluster_zone"); !ok || val != "us-east" {
		t.Errorf("restored fsm missing cluster_zone: %s", val)
	}
	if fsm2.AppliedCount() != 2 {
		t.Errorf("expected applied count 2, got %d", fsm2.AppliedCount())
	}
}

func TestStateMachine_Concurrency(t *testing.T) {
	fsm := NewStateMachine()
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			entry := LogEntry{
				Index: uint64(id + 1),
				Term:  1,
				Type:  CmdAddBlacklist,
				Data:  []byte(`{"container_id":"c-` + string(rune('a'+id)) + `","reason":"test"}`),
			}
			_, _ = fsm.Apply(entry)
			_ = fsm.GetBlacklist()
			_ = fsm.IsBlacklisted("c-a")
		}(i)
	}

	wg.Wait()
	if fsm.AppliedCount() != 20 {
		t.Errorf("expected 20 applied commands, got %d", fsm.AppliedCount())
	}
}
