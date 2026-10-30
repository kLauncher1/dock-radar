package raft

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
)

// Engine is the master orchestrator of Raft consensus, leader election, and log replication.
type Engine struct {
	mu           sync.Mutex
	cfg          RaftConfig
	fsm          *StateMachine
	log          *RaftLog
	transport    *HTTPTransport
	currentTerm  uint64
	votedFor     string
	state        RaftState
	leaderID     string
	commitIndex  uint64
	lastApplied  uint64
	peers        []string
	matchIndex   map[string]uint64
	nextIndex    map[string]uint64
	startTime    time.Time
	auditLogger  *audit.Logger
	alertDispatcher *alert.Dispatcher

	electionResetChan chan struct{}
	stopChan          chan struct{}
	stopped           bool
}

// NewEngine initializes a Raft consensus engine.
func NewEngine(
	cfg RaftConfig,
	fsm *StateMachine,
	transport *HTTPTransport,
	auditLogger *audit.Logger,
	alertDispatcher *alert.Dispatcher,
) (*Engine, error) {
	if err := ValidateRaftConfig(cfg); err != nil {
		return nil, err
	}
	if fsm == nil {
		fsm = NewStateMachine()
	}
	if transport == nil {
		transport = NewHTTPTransport(cfg.HeartbeatInterval, "")
	}

	e := &Engine{
		cfg:               cfg,
		fsm:               fsm,
		log:               NewRaftLog(),
		transport:         transport,
		currentTerm:       0,
		votedFor:          "",
		state:             StateFollower,
		leaderID:          "",
		commitIndex:       0,
		lastApplied:       0,
		peers:             make([]string, len(cfg.Peers)),
		matchIndex:        make(map[string]uint64),
		nextIndex:         make(map[string]uint64),
		startTime:         time.Now().UTC(),
		auditLogger:       auditLogger,
		alertDispatcher:   alertDispatcher,
		electionResetChan: make(chan struct{}, 16),
		stopChan:          make(chan struct{}),
	}
	copy(e.peers, cfg.Peers)

	// If standalone (no peers configured), node starts as Follower and will elect itself Leader on first tick
	return e, nil
}

// Start begins background election and heartbeat loops.
func (e *Engine) Start(ctx context.Context) {
	e.mu.Lock()
	if !e.cfg.Enabled {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()

	go e.runLoop(ctx)
}

// Stop terminates background consensus goroutines.
func (e *Engine) Stop() {
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return
	}
	e.stopped = true
	close(e.stopChan)
	e.mu.Unlock()
}

func (e *Engine) randomElectionTimeout() time.Duration {
	min := e.cfg.ElectionTimeoutMin
	max := e.cfg.ElectionTimeoutMax
	delta := max - min
	if delta <= 0 {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(delta)))
	if err != nil {
		return min
	}
	return min + time.Duration(n.Int64())
}

func (e *Engine) resetElectionTimer() {
	select {
	case e.electionResetChan <- struct{}{}:
	default:
	}
}

func (e *Engine) runLoop(ctx context.Context) {
	electionTimer := time.NewTimer(e.randomElectionTimeout())
	defer electionTimer.Stop()

	heartbeatTicker := time.NewTicker(e.cfg.HeartbeatInterval)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopChan:
			return

		case <-e.electionResetChan:
			if !electionTimer.Stop() {
				select {
				case <-electionTimer.C:
				default:
				}
			}
			electionTimer.Reset(e.randomElectionTimeout())

		case <-electionTimer.C:
			e.handleElectionTimeout(ctx)
			electionTimer.Reset(e.randomElectionTimeout())

		case <-heartbeatTicker.C:
			e.handleHeartbeatTick(ctx)
		}
	}
}

func (e *Engine) handleElectionTimeout(ctx context.Context) {
	e.mu.Lock()
	if e.state == StateLeader {
		e.mu.Unlock()
		return
	}

	// Transition to candidate
	e.state = StateCandidate
	e.currentTerm++
	e.votedFor = e.cfg.NodeID
	e.leaderID = ""
	term := e.currentTerm
	lastIndex, lastTerm := e.log.LastIndexTerm()
	peers := make([]string, len(e.peers))
	copy(peers, e.peers)
	e.mu.Unlock()

	totalNodes := len(peers) + 1
	quorum := (totalNodes / 2) + 1

	// Standalone cluster case
	if totalNodes == 1 {
		e.mu.Lock()
		if e.currentTerm == term && e.state == StateCandidate {
			e.state = StateLeader
			e.leaderID = e.cfg.NodeID
			e.logEvent("raft_leader_elected", map[string]any{
				"term":       term,
				"node_id":    e.cfg.NodeID,
				"standalone": true,
			})
		}
		e.mu.Unlock()
		return
	}

	// Solicit votes concurrently
	type voteRes struct {
		peer    string
		granted bool
		term    uint64
	}
	voteChan := make(chan voteRes, len(peers))
	for _, peer := range peers {
		go func(p string) {
			reqCtx, cancel := context.WithTimeout(ctx, e.cfg.ElectionTimeoutMin)
			defer cancel()

			reply, err := e.transport.RequestVote(reqCtx, p, RequestVoteArgs{
				Term:         term,
				CandidateID:  e.cfg.NodeID,
				LastLogIndex: lastIndex,
				LastLogTerm:  lastTerm,
			})
			if err != nil {
				voteChan <- voteRes{peer: p, granted: false, term: 0}
				return
			}
			voteChan <- voteRes{peer: p, granted: reply.VoteGranted, term: reply.Term}
		}(peer)
	}

	votesReceived := 1 // self vote
	for i := 0; i < len(peers); i++ {
		res := <-voteChan
		e.mu.Lock()
		if res.term > e.currentTerm {
			e.currentTerm = res.term
			e.state = StateFollower
			e.votedFor = ""
			e.leaderID = ""
			e.mu.Unlock()
			return
		}
		if res.granted {
			votesReceived++
		}
		e.mu.Unlock()
	}

	e.mu.Lock()
	if e.state == StateCandidate && e.currentTerm == term && votesReceived >= quorum {
		e.state = StateLeader
		e.leaderID = e.cfg.NodeID
		for _, p := range e.peers {
			e.nextIndex[p] = lastIndex + 1
			e.matchIndex[p] = 0
		}
		e.logEvent("raft_leader_elected", map[string]any{
			"term":     term,
			"node_id":  e.cfg.NodeID,
			"votes":    votesReceived,
			"quorum":   quorum,
		})
		e.mu.Unlock()
		e.sendHeartbeats(ctx)
		return
	}
	e.mu.Unlock()
}

func (e *Engine) handleHeartbeatTick(ctx context.Context) {
	e.mu.Lock()
	if e.state != StateLeader {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()

	e.sendHeartbeats(ctx)
}

func (e *Engine) sendHeartbeats(ctx context.Context) {
	e.mu.Lock()
	term := e.currentTerm
	leaderID := e.cfg.NodeID
	commitIndex := e.commitIndex
	peers := make([]string, len(e.peers))
	copy(peers, e.peers)
	e.mu.Unlock()

	for _, peer := range peers {
		go func(p string) {
			e.mu.Lock()
			nextIdx := e.nextIndex[p]
			if nextIdx == 0 {
				nextIdx = 1
			}
			prevIndex := nextIdx - 1
			prevTerm := uint64(0)
			if prevEntry, ok := e.log.Get(prevIndex); ok {
				prevTerm = prevEntry.Term
			}
			entries := e.log.Slice(nextIdx)
			e.mu.Unlock()

			reqCtx, cancel := context.WithTimeout(ctx, e.cfg.HeartbeatInterval)
			defer cancel()

			reply, err := e.transport.AppendEntries(reqCtx, p, AppendEntriesArgs{
				Term:         term,
				LeaderID:     leaderID,
				PrevLogIndex: prevIndex,
				PrevLogTerm:  prevTerm,
				Entries:      entries,
				LeaderCommit: commitIndex,
			})
			if err != nil {
				return
			}

			e.mu.Lock()
			defer e.mu.Unlock()

			if reply.Term > e.currentTerm {
				e.currentTerm = reply.Term
				e.state = StateFollower
				e.votedFor = ""
				e.leaderID = ""
				return
			}

			if e.state != StateLeader || e.currentTerm != term {
				return
			}

			if reply.Success {
				if len(entries) > 0 {
					e.nextIndex[p] = entries[len(entries)-1].Index + 1
					e.matchIndex[p] = entries[len(entries)-1].Index
					e.checkAdvanceCommitIndex()
				}
			} else {
				if e.nextIndex[p] > 1 {
					e.nextIndex[p]--
				}
			}
		}(peer)
	}
}

func (e *Engine) checkAdvanceCommitIndex() {
	lastIndex, _ := e.log.LastIndexTerm()
	quorum := ((len(e.peers) + 1) / 2) + 1

	for n := lastIndex; n > e.commitIndex; n-- {
		entry, ok := e.log.Get(n)
		if !ok || entry.Term != e.currentTerm {
			continue
		}

		matches := 1 // self
		for _, peer := range e.peers {
			if e.matchIndex[peer] >= n {
				matches++
			}
		}

		if matches >= quorum {
			e.commitIndex = n
			e.applyCommittedEntries()
			break
		}
	}
}

func (e *Engine) applyCommittedEntries() {
	for e.commitIndex > e.lastApplied {
		e.lastApplied++
		entry, ok := e.log.Get(e.lastApplied)
		if ok {
			_, _ = e.fsm.Apply(entry)
		}
	}
}

// Propose appends a new state command and replicates it to followers until committed.
func (e *Engine) Propose(ctx context.Context, cmdType CommandType, data []byte) (*ApplyResult, error) {
	e.mu.Lock()
	if e.state != StateLeader {
		leader := e.leaderID
		e.mu.Unlock()
		return nil, fmt.Errorf("%w: current leader is %q", ErrNotLeader, leader)
	}

	entry := LogEntry{
		Term:      e.currentTerm,
		Type:      cmdType,
		Data:      data,
		Timestamp: time.Now().UTC(),
	}
	idx := e.log.Append(entry)
	entry.Index = idx

	totalNodes := len(e.peers) + 1
	if totalNodes == 1 {
		// Standalone: immediate commit and apply
		e.commitIndex = idx
		e.applyCommittedEntries()
		res, err := e.fsm.Apply(entry)
		e.mu.Unlock()
		return res, err
	}
	e.mu.Unlock()

	// Replicate to cluster
	e.sendHeartbeats(ctx)

	// Wait for commit index to advance
	deadline := time.Now().Add(5 * time.Second)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			e.mu.Lock()
			if e.state != StateLeader {
				e.mu.Unlock()
				return nil, ErrNotLeader
			}
			if e.commitIndex >= idx {
				e.applyCommittedEntries()
				e.mu.Unlock()
				return &ApplyResult{
					Success: true,
					Index:   idx,
					Term:    entry.Term,
					Message: fmt.Sprintf("command %s committed at index %d", cmdType, idx),
				}, nil
			}
			if time.Now().After(deadline) {
				e.mu.Unlock()
				return nil, errors.New("timeout waiting for quorum commit")
			}
			e.mu.Unlock()
		}
	}
}
