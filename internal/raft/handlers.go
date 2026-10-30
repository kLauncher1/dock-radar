package raft

import (
	"fmt"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
)

// HandleRequestVote processes an incoming RequestVote RPC from a candidate peer.
func (e *Engine) HandleRequestVote(args RequestVoteArgs) RequestVoteReply {
	e.mu.Lock()
	defer e.mu.Unlock()

	if args.Term < e.currentTerm {
		return RequestVoteReply{Term: e.currentTerm, VoteGranted: false, Reason: "term too low"}
	}

	if args.Term > e.currentTerm {
		e.currentTerm = args.Term
		e.state = StateFollower
		e.votedFor = ""
		e.leaderID = ""
	}

	lastIndex, lastTerm := e.log.LastIndexTerm()
	logOk := args.LastLogTerm > lastTerm || (args.LastLogTerm == lastTerm && args.LastLogIndex >= lastIndex)

	canVote := e.votedFor == "" || e.votedFor == args.CandidateID
	if canVote && logOk {
		e.votedFor = args.CandidateID
		e.resetElectionTimer()
		return RequestVoteReply{Term: e.currentTerm, VoteGranted: true, Reason: "vote granted"}
	}

	reason := "already voted for another candidate"
	if !logOk {
		reason = "candidate log not sufficiently up to date"
	}
	return RequestVoteReply{Term: e.currentTerm, VoteGranted: false, Reason: reason}
}

// HandleAppendEntries processes an incoming AppendEntries RPC from the cluster leader.
func (e *Engine) HandleAppendEntries(args AppendEntriesArgs) AppendEntriesReply {
	e.mu.Lock()
	defer e.mu.Unlock()

	if args.Term < e.currentTerm {
		return AppendEntriesReply{Term: e.currentTerm, Success: false, Reason: "term too low"}
	}

	if args.Term > e.currentTerm || e.state == StateCandidate {
		e.currentTerm = args.Term
		e.state = StateFollower
		e.votedFor = ""
	}
	e.leaderID = args.LeaderID
	e.resetElectionTimer()

	// Check log consistency
	if args.PrevLogIndex > 0 {
		prevEntry, ok := e.log.Get(args.PrevLogIndex)
		if !ok || prevEntry.Term != args.PrevLogTerm {
			return AppendEntriesReply{
				Term:    e.currentTerm,
				Success: false,
				Reason:  fmt.Sprintf("log mismatch at prevIndex %d", args.PrevLogIndex),
			}
		}
	}

	// Append entries, truncating conflicting suffixes if needed
	for _, entry := range args.Entries {
		if existing, ok := e.log.Get(entry.Index); ok {
			if existing.Term != entry.Term {
				e.log.TruncateSuffix(entry.Index)
				e.log.Append(entry)
			}
		} else {
			e.log.Append(entry)
		}
	}

	// Advance commit index and apply
	if args.LeaderCommit > e.commitIndex {
		lastIndex, _ := e.log.LastIndexTerm()
		if args.LeaderCommit < lastIndex {
			e.commitIndex = args.LeaderCommit
		} else {
			e.commitIndex = lastIndex
		}
		e.applyCommittedEntries()
	}

	lastIndex, _ := e.log.LastIndexTerm()
	return AppendEntriesReply{
		Term:       e.currentTerm,
		Success:    true,
		MatchIndex: lastIndex,
	}
}

// StepDown causes the node to relinquish leadership or candidate role and become a follower.
func (e *Engine) StepDown() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.state = StateFollower
	e.votedFor = ""
	e.leaderID = ""
	e.resetElectionTimer()
	e.logEvent("raft_step_down", map[string]any{"node_id": e.cfg.NodeID, "term": e.currentTerm})
	return nil
}

// AddPeer dynamically adds a peer node address to the consensus cluster.
func (e *Engine) AddPeer(peer string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, p := range e.peers {
		if p == peer {
			return nil
		}
	}
	e.peers = append(e.peers, peer)
	return nil
}

// RemovePeer dynamically removes a peer node from the consensus cluster.
func (e *Engine) RemovePeer(peer string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	newPeers := make([]string, 0, len(e.peers))
	for _, p := range e.peers {
		if p != peer {
			newPeers = append(newPeers, p)
		}
	}
	e.peers = newPeers
	delete(e.nextIndex, peer)
	delete(e.matchIndex, peer)
	return nil
}

// TriggerSnapshot manually compacts the Raft log against current FSM state.
func (e *Engine) TriggerSnapshot() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	snap, err := e.fsm.Snapshot()
	if err != nil {
		return err
	}
	_ = snap
	lastIdx := e.commitIndex
	lastTerm := uint64(0)
	if entry, ok := e.log.Get(lastIdx); ok {
		lastTerm = entry.Term
	}
	e.log.Compact(lastIdx, lastTerm)
	return nil
}

// Status returns real-time Raft consensus metrics and operational state.
func (e *Engine) Status() RaftStatus {
	e.mu.Lock()
	defer e.mu.Unlock()

	lastIdx, lastTerm := e.log.LastIndexTerm()
	peersCopy := make([]string, len(e.peers))
	copy(peersCopy, e.peers)

	totalNodes := len(peersCopy) + 1
	quorum := (totalNodes / 2) + 1

	return RaftStatus{
		NodeID:               e.cfg.NodeID,
		State:                string(e.state),
		Term:                 e.currentTerm,
		LeaderID:             e.leaderID,
		CommitIndex:          e.commitIndex,
		LastApplied:          e.lastApplied,
		LastLogIndex:         lastIdx,
		LastLogTerm:          lastTerm,
		Peers:                peersCopy,
		PeerCount:            len(peersCopy),
		QuorumSize:           quorum,
		IsLeader:             e.state == StateLeader,
		LogEntriesCount:      e.log.Len(),
		AppliedCommandsCount: e.fsm.AppliedCount(),
		UptimeSeconds:        uint64(time.Since(e.startTime).Seconds()),
	}
}

// FSM returns the underlying replicated state machine.
func (e *Engine) FSM() *StateMachine {
	return e.fsm
}

func (e *Engine) logEvent(action string, details map[string]any) {
	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  action,
			Target:  e.cfg.NodeID,
			Details: details,
		})
	}
}
