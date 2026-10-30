package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/raft"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// RaftProposeRequest captures command parameters for cluster consensus proposal.
type RaftProposeRequest struct {
	Type raft.CommandType `json:"type"`
	Data json.RawMessage  `json:"data"`
}

// RaftPeerRequest captures peer address inputs for cluster membership modifications.
type RaftPeerRequest struct {
	Peer string `json:"peer"`
}

// handleRaftStatus returns the consensus operational state and node role.
func (h *HandlerConfig) handleRaftStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.RaftEngine == nil {
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"enabled": false,
			"state":   "disabled",
		})
		return
	}
	writeJSONResponse(w, http.StatusOK, h.RaftEngine.Status())
}

// handleRaftFSM returns current synchronized replicated state machine contents.
func (h *HandlerConfig) handleRaftFSM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.RaftEngine == nil {
		http.Error(w, "raft consensus engine unavailable", http.StatusServiceUnavailable)
		return
	}

	fsm := h.RaftEngine.FSM()
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"healing_policy": fsm.GetHealingPolicy(),
		"blacklist":      fsm.GetBlacklist(),
		"node_states":    fsm.GetNodeStates(),
		"configs":        fsm.GetAllConfigs(),
		"applied_count":  fsm.AppliedCount(),
	})
}

// handleRaftPropose replicates a state command to the consensus cluster (leader only).
func (h *HandlerConfig) handleRaftPropose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}
	if h.RaftEngine == nil {
		http.Error(w, "raft consensus engine unavailable", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read payload: %v", err), http.StatusBadRequest)
		return
	}

	var req RaftProposeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	if req.Type == "" {
		http.Error(w, "command type is required", http.StatusBadRequest)
		return
	}
	if len(req.Data) == 0 {
		http.Error(w, "command data is required", http.StatusBadRequest)
		return
	}

	res, err := h.RaftEngine.Propose(r.Context(), req.Type, req.Data)
	if err != nil {
		if strings.Contains(err.Error(), raft.ErrNotLeader.Error()) {
			st := h.RaftEngine.Status()
			w.Header().Set("X-Raft-Leader", st.LeaderID)
			http.Error(w, fmt.Sprintf("not leader; leader is %q: %v", st.LeaderID, err), http.StatusConflict)
			return
		}
		http.Error(w, fmt.Sprintf("failed to propose command: %v", err), http.StatusInternalServerError)
		return
	}

	if h.AuditLogger != nil {
		h.AuditLogger.Log(audit.AuditEvent{
			Action:  "raft_command_proposed",
			Target:  string(req.Type),
			Details: map[string]any{"index": res.Index, "term": res.Term},
		})
	}

	writeJSONResponse(w, http.StatusOK, res)
}

// handleRaftPeers manages cluster membership inspection and additions/removals.
func (h *HandlerConfig) handleRaftPeers(w http.ResponseWriter, r *http.Request) {
	if h.RaftEngine == nil {
		http.Error(w, "raft consensus engine unavailable", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		st := h.RaftEngine.Status()
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"peers":       st.Peers,
			"peer_count":  st.PeerCount,
			"quorum_size": st.QuorumSize,
		})

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		var req RaftPeerRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		req.Peer = strings.TrimSpace(req.Peer)
		if req.Peer == "" {
			http.Error(w, "peer address is required", http.StatusBadRequest)
			return
		}
		if err := h.RaftEngine.AddPeer(req.Peer); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Action:  "raft_peer_added",
				Target:  req.Peer,
				Details: map[string]any{"peer": req.Peer},
			})
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{"success": true, "peer": req.Peer})

	case http.MethodDelete:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		peer := r.URL.Query().Get("peer")
		if peer == "" {
			var req RaftPeerRequest
			_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req)
			peer = req.Peer
		}
		peer = strings.TrimSpace(peer)
		if peer == "" {
			http.Error(w, "peer address is required", http.StatusBadRequest)
			return
		}
		if err := h.RaftEngine.RemovePeer(peer); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Action:  "raft_peer_removed",
				Target:  peer,
				Details: map[string]any{"peer": peer},
			})
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{"success": true, "peer": peer})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRaftStepDown forces leader to step down for manual failover drills.
func (h *HandlerConfig) handleRaftStepDown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}
	if h.RaftEngine == nil {
		http.Error(w, "raft consensus engine unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := h.RaftEngine.StepDown(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "node stepped down to follower",
	})
}

// handleRaftSnapshot triggers on-demand state machine snapshot compaction.
func (h *HandlerConfig) handleRaftSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}
	if h.RaftEngine == nil {
		http.Error(w, "raft consensus engine unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := h.RaftEngine.TriggerSnapshot(); err != nil {
		http.Error(w, fmt.Sprintf("snapshot failed: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "state machine snapshot created and log compacted",
	})
}

// handleRaftRPCVote handles incoming RequestVote RPC from candidate peers.
func (h *HandlerConfig) handleRaftRPCVote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.RaftEngine == nil {
		http.Error(w, "raft consensus engine unavailable", http.StatusServiceUnavailable)
		return
	}

	var args raft.RequestVoteArgs
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&args); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	reply := h.RaftEngine.HandleRequestVote(args)
	writeJSONResponse(w, http.StatusOK, reply)
}

// handleRaftRPCAppend handles incoming AppendEntries RPC from cluster leader.
func (h *HandlerConfig) handleRaftRPCAppend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.RaftEngine == nil {
		http.Error(w, "raft consensus engine unavailable", http.StatusServiceUnavailable)
		return
	}

	var args raft.AppendEntriesArgs
	if err := json.NewDecoder(io.LimitReader(r.Body, 1048576)).Decode(&args); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	reply := h.RaftEngine.HandleAppendEntries(args)
	writeJSONResponse(w, http.StatusOK, reply)
}
