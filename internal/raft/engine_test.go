package raft

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
)

func TestEngine_SingleNodeAutoLeader(t *testing.T) {
	cfg := DefaultRaftConfig()
	cfg.NodeID = "standalone-1"
	cfg.ElectionTimeoutMin = 50 * time.Millisecond
	cfg.ElectionTimeoutMax = 100 * time.Millisecond
	cfg.HeartbeatInterval = 30 * time.Millisecond
	cfg.Peers = nil

	auditLog := audit.NewLogger(100)
	engine, err := NewEngine(cfg, nil, nil, auditLog, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx)

	// Wait for election timeout to trigger and elect leader
	deadline := time.Now().Add(500 * time.Millisecond)
	var st RaftStatus
	for time.Now().Before(deadline) {
		st = engine.Status()
		if st.IsLeader {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !st.IsLeader {
		t.Fatalf("expected standalone node to become leader, status: %+v", st)
	}
	if st.Term < 1 {
		t.Errorf("expected term >= 1, got %d", st.Term)
	}
	if st.QuorumSize != 1 {
		t.Errorf("expected quorum size 1 for standalone, got %d", st.QuorumSize)
	}

	engine.Stop()
}

func TestEngine_ProposeAndCommit_SingleNode(t *testing.T) {
	cfg := DefaultRaftConfig()
	cfg.NodeID = "node-propose"
	cfg.ElectionTimeoutMin = 50 * time.Millisecond
	cfg.ElectionTimeoutMax = 100 * time.Millisecond
	cfg.HeartbeatInterval = 30 * time.Millisecond
	cfg.Peers = nil

	fsm := NewStateMachine()
	engine, err := NewEngine(cfg, fsm, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.Start(ctx)

	// Wait for leader
	time.Sleep(150 * time.Millisecond)

	res, err := engine.Propose(ctx, CmdClusterConfig, []byte(`{"key":"mesh_secret","value":"s3cr3t"}`))
	if err != nil {
		t.Fatalf("Propose failed: %v", err)
	}
	if !res.Success || res.Index != 1 {
		t.Errorf("unexpected propose result: %+v", res)
	}

	val, found := fsm.GetConfig("mesh_secret")
	if !found || val != "s3cr3t" {
		t.Errorf("expected mesh_secret=s3cr3t in FSM, got %s (found: %v)", val, found)
	}

	st := engine.Status()
	if st.CommitIndex != 1 || st.LastApplied != 1 {
		t.Errorf("expected commit and applied index 1, got commit=%d applied=%d", st.CommitIndex, st.LastApplied)
	}

	engine.Stop()
}

func TestEngine_RequestVoteAndAppendEntries_Handlers(t *testing.T) {
	cfg := DefaultRaftConfig()
	cfg.NodeID = "follower-node"
	fsm := NewStateMachine()
	engine, err := NewEngine(cfg, fsm, nil, nil, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// 1. RequestVote from a candidate with higher term
	vReply := engine.HandleRequestVote(RequestVoteArgs{
		Term:         2,
		CandidateID:  "candidate-alpha",
		LastLogIndex: 0,
		LastLogTerm:  0,
	})
	if !vReply.VoteGranted || vReply.Term != 2 {
		t.Errorf("expected vote granted, got %+v", vReply)
	}

	// 2. RequestVote from second candidate in same term (should reject)
	vReply2 := engine.HandleRequestVote(RequestVoteArgs{
		Term:         2,
		CandidateID:  "candidate-beta",
		LastLogIndex: 0,
		LastLogTerm:  0,
	})
	if vReply2.VoteGranted {
		t.Errorf("expected second vote in same term to be rejected")
	}

	// 3. AppendEntries from valid leader
	aReply := engine.HandleAppendEntries(AppendEntriesArgs{
		Term:         2,
		LeaderID:     "candidate-alpha",
		PrevLogIndex: 0,
		PrevLogTerm:  0,
		Entries: []LogEntry{
			{Index: 1, Term: 2, Type: CmdClusterConfig, Data: []byte(`{"key":"k1","value":"v1"}`)},
		},
		LeaderCommit: 1,
	})
	if !aReply.Success || aReply.MatchIndex != 1 {
		t.Errorf("expected AppendEntries success, got %+v", aReply)
	}

	// Verify state applied to FSM
	val, ok := fsm.GetConfig("k1")
	if !ok || val != "v1" {
		t.Errorf("expected config k1=v1 in FSM, got %s", val)
	}

	// 4. AppendEntries with stale term (should reject)
	aReplyStale := engine.HandleAppendEntries(AppendEntriesArgs{
		Term:     1,
		LeaderID: "old-leader",
	})
	if aReplyStale.Success {
		t.Errorf("expected AppendEntries with stale term to be rejected")
	}
}

func TestEngine_AddRemovePeer_And_StepDown(t *testing.T) {
	cfg := DefaultRaftConfig()
	cfg.NodeID = "peer-mgr"
	engine, _ := NewEngine(cfg, nil, nil, nil, nil)

	_ = engine.AddPeer("10.0.1.2:9080")
	_ = engine.AddPeer("10.0.1.3:9080")

	st := engine.Status()
	if st.PeerCount != 2 || st.QuorumSize != 2 { // 3 total nodes -> quorum 2
		t.Errorf("expected 2 peers and quorum 2, got peers=%d quorum=%d", st.PeerCount, st.QuorumSize)
	}

	_ = engine.RemovePeer("10.0.1.2:9080")
	st = engine.Status()
	if st.PeerCount != 1 || st.QuorumSize != 2 { // 2 total nodes -> quorum 2
		t.Errorf("expected 1 peer and quorum 2, got peers=%d quorum=%d", st.PeerCount, st.QuorumSize)
	}

	_ = engine.StepDown()
	st = engine.Status()
	if st.State != string(StateFollower) {
		t.Errorf("expected follower after step down, got %s", st.State)
	}
}

func TestEngine_ClusterThreeNodes_ElectionAndReplication(t *testing.T) {
	// Create 3 simulated nodes with HTTP test servers
	var (
		engines [3]*Engine
		servers [3]*httptest.Server
	)

	// Step 1: Initialize engines
	for i := 0; i < 3; i++ {
		cfg := DefaultRaftConfig()
		cfg.NodeID = "node-" + string(rune('1'+i))
		cfg.ElectionTimeoutMin = 100 * time.Millisecond
		cfg.ElectionTimeoutMax = 200 * time.Millisecond
		cfg.HeartbeatInterval = 40 * time.Millisecond

		eng, err := NewEngine(cfg, NewStateMachine(), nil, nil, nil)
		if err != nil {
			t.Fatalf("failed to create engine %d: %v", i, err)
		}
		engines[i] = eng
	}

	// Step 2: Spin up HTTP mock handlers forwarding to engine RPCs
	for i := 0; i < 3; i++ {
		eng := engines[i]
		mux := http.NewServeMux()
		mux.HandleFunc("/api/raft/rpc/vote", func(w http.ResponseWriter, r *http.Request) {
			var args RequestVoteArgs
			_ = json.NewDecoder(r.Body).Decode(&args)
			reply := eng.HandleRequestVote(args)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(reply)
		})
		mux.HandleFunc("/api/raft/rpc/append", func(w http.ResponseWriter, r *http.Request) {
			var args AppendEntriesArgs
			_ = json.NewDecoder(r.Body).Decode(&args)
			reply := eng.HandleAppendEntries(args)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(reply)
		})
		servers[i] = httptest.NewServer(mux)
	}
	defer func() {
		for i := 0; i < 3; i++ {
			servers[i].Close()
			engines[i].Stop()
		}
	}()

	// Step 3: Wire peer URLs
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			if i != j {
				_ = engines[i].AddPeer(servers[j].URL)
			}
		}
	}

	// Step 4: Start background loops
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < 3; i++ {
		engines[i].Start(ctx)
	}

	// Step 5: Wait for a leader to be elected
	var leader *Engine
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for i := 0; i < 3; i++ {
			if engines[i].Status().IsLeader {
				leader = engines[i]
				break
			}
		}
		if leader != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if leader == nil {
		t.Fatalf("timed out waiting for leader election among 3 nodes")
	}

	// Step 6: Propose command on leader and verify replication to majority
	res, err := leader.Propose(ctx, CmdAddBlacklist, []byte(`{"container_id":"rogue-c1","reason":"quarantined"}`))
	if err != nil {
		t.Fatalf("propose on cluster leader failed: %v", err)
	}
	if !res.Success {
		t.Errorf("propose returned success=false")
	}

	// Verify blacklist in leader's FSM
	if !leader.FSM().IsBlacklisted("rogue-c1") {
		t.Errorf("leader FSM does not have rogue-c1 blacklisted")
	}
}

func TestEngine_SnapshotCompaction(t *testing.T) {
	cfg := DefaultRaftConfig()
	cfg.NodeID = "node-snap"
	cfg.ElectionTimeoutMin = 50 * time.Millisecond
	cfg.ElectionTimeoutMax = 100 * time.Millisecond
	cfg.HeartbeatInterval = 30 * time.Millisecond
	cfg.Peers = nil

	fsm := NewStateMachine()
	engine, _ := NewEngine(cfg, fsm, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine.Start(ctx)

	// Wait for leader
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if engine.Status().IsLeader {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	res1, err := engine.Propose(ctx, CmdClusterConfig, []byte(`{"key":"k1","value":"v1"}`))
	if err != nil {
		t.Fatalf("propose 1 failed: %v", err)
	}
	if !res1.Success {
		t.Fatalf("propose 1 was not successful")
	}

	res2, err := engine.Propose(ctx, CmdClusterConfig, []byte(`{"key":"k2","value":"v2"}`))
	if err != nil {
		t.Fatalf("propose 2 failed: %v", err)
	}
	if !res2.Success {
		t.Fatalf("propose 2 was not successful")
	}

	err = engine.TriggerSnapshot()
	if err != nil {
		t.Fatalf("TriggerSnapshot failed: %v", err)
	}

	st := engine.Status()
	if st.CommitIndex != 2 {
		t.Errorf("expected commit index 2, got %d", st.CommitIndex)
	}

	engine.Stop()
}
