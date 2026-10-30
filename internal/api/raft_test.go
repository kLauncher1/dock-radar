package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/raft"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestRaftHandler(t *testing.T) (*HandlerConfig, *raft.Engine) {
	cfg := raft.DefaultRaftConfig()
	cfg.NodeID = "api-test-node"
	cfg.ElectionTimeoutMin = 50 * time.Millisecond
	cfg.ElectionTimeoutMax = 100 * time.Millisecond
	cfg.HeartbeatInterval = 30 * time.Millisecond
	cfg.Peers = nil

	fsm := raft.NewStateMachine()
	auditLog := audit.NewLogger(100)
	eng, err := raft.NewEngine(cfg, fsm, nil, auditLog, nil)
	if err != nil {
		t.Fatalf("failed to create raft engine: %v", err)
	}

	h := &HandlerConfig{
		RaftEngine:  eng,
		AuditLogger: auditLog,
		TokenAuth:   security.NewTokenAuth("admin-secret", "viewer-secret", true),
		AllowRemote: true,
	}
	return h, eng
}

func TestHandleRaftStatus_ViewerAccess(t *testing.T) {
	h, _ := setupTestRaftHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/raft/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret")
	w := httptest.NewRecorder()

	h.handleRaftStatus(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var st raft.RaftStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("failed to parse status JSON: %v", err)
	}
	if st.NodeID != "api-test-node" {
		t.Errorf("expected node ID api-test-node, got %s", st.NodeID)
	}
}

func TestHandleRaftFSM_ViewerAccess(t *testing.T) {
	h, eng := setupTestRaftHandler(t)

	// Add a blacklist entry to FSM
	_, _ = eng.FSM().Apply(raft.LogEntry{
		Index: 1, Term: 1, Type: raft.CmdAddBlacklist,
		Data: []byte(`{"container_id":"bad-worker","reason":"crashed"}`),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/raft/fsm", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret")
	w := httptest.NewRecorder()

	h.handleRaftFSM(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse fsm JSON: %v", err)
	}
	if resp["applied_count"].(float64) < 1 {
		t.Errorf("expected applied_count >= 1, got %v", resp["applied_count"])
	}
}

func TestHandleRaftPropose_AdminOnly(t *testing.T) {
	h, eng := setupTestRaftHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng.Start(ctx)
	defer eng.Stop()

	// Wait for standalone node to become leader
	time.Sleep(150 * time.Millisecond)

	// Unauthorized attempt (viewer token)
	reqViewer := httptest.NewRequest(http.MethodPost, "/api/raft/propose", bytes.NewReader([]byte(`{}`)))
	reqViewer.Header.Set("Authorization", "Bearer viewer-secret")
	wViewer := httptest.NewRecorder()
	h.handleRaftPropose(wViewer, reqViewer)
	if wViewer.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for viewer, got %d", wViewer.Code)
	}

	// Authorized admin attempt
	payload := `{"type":"cluster_config","data":{"key":"log_level","value":"debug"}}`
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/raft/propose", bytes.NewReader([]byte(payload)))
	reqAdmin.Header.Set("Authorization", "Bearer admin-secret")
	wAdmin := httptest.NewRecorder()
	h.handleRaftPropose(wAdmin, reqAdmin)
	if wAdmin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin propose, got %d: %s", wAdmin.Code, wAdmin.Body.String())
	}

	var res raft.ApplyResult
	if err := json.Unmarshal(wAdmin.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode ApplyResult: %v", err)
	}
	if !res.Success {
		t.Errorf("expected res.Success=true")
	}
}

func TestHandleRaftPeers_CRUD(t *testing.T) {
	h, _ := setupTestRaftHandler(t)

	// 1. GET peers
	reqGet := httptest.NewRequest(http.MethodGet, "/api/raft/peers", nil)
	reqGet.Header.Set("Authorization", "Bearer viewer-secret")
	wGet := httptest.NewRecorder()
	h.handleRaftPeers(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET peers, got %d", wGet.Code)
	}

	// 2. POST peer (add)
	addPayload := `{"peer":"192.168.1.10:9080"}`
	reqAdd := httptest.NewRequest(http.MethodPost, "/api/raft/peers", bytes.NewReader([]byte(addPayload)))
	reqAdd.Header.Set("Authorization", "Bearer admin-secret")
	wAdd := httptest.NewRecorder()
	h.handleRaftPeers(wAdd, reqAdd)
	if wAdd.Code != http.StatusOK {
		t.Fatalf("expected 200 for POST peer, got %d: %s", wAdd.Code, wAdd.Body.String())
	}

	// 3. DELETE peer (remove)
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/raft/peers?peer=192.168.1.10:9080", nil)
	reqDel.Header.Set("Authorization", "Bearer admin-secret")
	wDel := httptest.NewRecorder()
	h.handleRaftPeers(wDel, reqDel)
	if wDel.Code != http.StatusOK {
		t.Fatalf("expected 200 for DELETE peer, got %d: %s", wDel.Code, wDel.Body.String())
	}
}

func TestHandleRaftStepDown_And_Snapshot(t *testing.T) {
	h, _ := setupTestRaftHandler(t)

	// StepDown
	reqStep := httptest.NewRequest(http.MethodPost, "/api/raft/stepdown", nil)
	reqStep.Header.Set("Authorization", "Bearer admin-secret")
	wStep := httptest.NewRecorder()
	h.handleRaftStepDown(wStep, reqStep)
	if wStep.Code != http.StatusOK {
		t.Fatalf("expected 200 for stepdown, got %d", wStep.Code)
	}

	// Snapshot
	reqSnap := httptest.NewRequest(http.MethodPost, "/api/raft/snapshot", nil)
	reqSnap.Header.Set("Authorization", "Bearer admin-secret")
	wSnap := httptest.NewRecorder()
	h.handleRaftSnapshot(wSnap, reqSnap)
	if wSnap.Code != http.StatusOK {
		t.Fatalf("expected 200 for snapshot, got %d", wSnap.Code)
	}
}

func TestHandleRaftRPCVoteAndAppend(t *testing.T) {
	h, _ := setupTestRaftHandler(t)

	// Vote RPC
	votePayload := `{"term":1,"candidate_id":"candidate-node","last_log_index":0,"last_log_term":0}`
	reqVote := httptest.NewRequest(http.MethodPost, "/api/raft/rpc/vote", bytes.NewReader([]byte(votePayload)))
	wVote := httptest.NewRecorder()
	h.handleRaftRPCVote(wVote, reqVote)
	if wVote.Code != http.StatusOK {
		t.Fatalf("expected 200 for RPC vote, got %d", wVote.Code)
	}

	var vReply raft.RequestVoteReply
	_ = json.Unmarshal(wVote.Body.Bytes(), &vReply)
	if !vReply.VoteGranted {
		t.Errorf("expected vote granted, got %+v", vReply)
	}

	// Append RPC
	appendPayload := `{"term":1,"leader_id":"candidate-node","prev_log_index":0,"prev_log_term":0,"entries":[],"leader_commit":0}`
	reqAppend := httptest.NewRequest(http.MethodPost, "/api/raft/rpc/append", bytes.NewReader([]byte(appendPayload)))
	wAppend := httptest.NewRecorder()
	h.handleRaftRPCAppend(wAppend, reqAppend)
	if wAppend.Code != http.StatusOK {
		t.Fatalf("expected 200 for RPC append, got %d", wAppend.Code)
	}

	var aReply raft.AppendEntriesReply
	_ = json.Unmarshal(wAppend.Body.Bytes(), &aReply)
	if !aReply.Success {
		t.Errorf("expected AppendEntries success, got %+v", aReply)
	}
}
