package raft

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBuildPeerURL(t *testing.T) {
	cases := []struct {
		peer     string
		endpoint string
		expected string
	}{
		{"127.0.0.1:9080", "/api/raft/rpc/vote", "http://127.0.0.1:9080/api/raft/rpc/vote"},
		{"http://10.0.1.2:9080", "api/raft/rpc/append", "http://10.0.1.2:9080/api/raft/rpc/append"},
		{"https://coordinator.local:9443", "/status", "https://coordinator.local:9443/status"},
	}

	for _, c := range cases {
		url, err := BuildPeerURL(c.peer, c.endpoint)
		if err != nil {
			t.Errorf("unexpected error for %q: %v", c.peer, err)
		}
		if url != c.expected {
			t.Errorf("got %q, want %q", url, c.expected)
		}
	}

	if _, err := BuildPeerURL("", "/endpoint"); err == nil {
		t.Errorf("expected error for empty peer, got nil")
	}
}

func TestHTTPTransport_RequestVote(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/raft/rpc/vote" {
			http.NotFound(w, r)
			return
		}
		var args RequestVoteArgs
		if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		reply := RequestVoteReply{
			Term:        args.Term,
			VoteGranted: true,
			Reason:      "granted",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer server.Close()

	tr := NewHTTPTransport(500*time.Millisecond, "test-token")
	reply, err := tr.RequestVote(context.Background(), server.URL, RequestVoteArgs{
		Term:         2,
		CandidateID:  "node-1",
		LastLogIndex: 10,
		LastLogTerm:  2,
	})
	if err != nil {
		t.Fatalf("RequestVote failed: %v", err)
	}
	if !reply.VoteGranted || reply.Term != 2 {
		t.Errorf("unexpected reply: %+v", reply)
	}
}

func TestHTTPTransport_AppendEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/raft/rpc/append" {
			http.NotFound(w, r)
			return
		}
		var args AppendEntriesArgs
		if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		reply := AppendEntriesReply{
			Term:       args.Term,
			Success:    true,
			MatchIndex: args.PrevLogIndex + uint64(len(args.Entries)),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer server.Close()

	tr := NewHTTPTransport(500*time.Millisecond, "")
	reply, err := tr.AppendEntries(context.Background(), server.URL, AppendEntriesArgs{
		Term:         3,
		LeaderID:     "node-leader",
		PrevLogIndex: 5,
		PrevLogTerm:  2,
		Entries: []LogEntry{
			{Index: 6, Term: 3, Type: CmdClusterConfig, Data: []byte("val")},
		},
		LeaderCommit: 5,
	})
	if err != nil {
		t.Fatalf("AppendEntries failed: %v", err)
	}
	if !reply.Success || reply.MatchIndex != 6 {
		t.Errorf("unexpected reply: %+v", reply)
	}
}

func TestHTTPTransport_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tr := NewHTTPTransport(50*time.Millisecond, "")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := tr.RequestVote(ctx, server.URL, RequestVoteArgs{Term: 1})
	if err == nil {
		t.Errorf("expected timeout error, got nil")
	}
}
