package metrics

import (
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/raft"
)

func TestAppendRaftMetrics_NilSafe(t *testing.T) {
	var b strings.Builder
	AppendRaftMetrics(&b, nil)
	if b.Len() != 0 {
		t.Errorf("expected empty string for nil status, got %q", b.String())
	}
}

func TestAppendRaftMetrics_LeaderAndFollower(t *testing.T) {
	status := &raft.RaftStatus{
		NodeID:               "coord-1",
		State:                "leader",
		Term:                 4,
		LeaderID:             "coord-1",
		CommitIndex:          42,
		LastApplied:          42,
		LastLogIndex:         45,
		LastLogTerm:          4,
		Peers:                []string{"10.0.1.2:9080", "10.0.1.3:9080"},
		PeerCount:            2,
		QuorumSize:           2,
		IsLeader:             true,
		LogEntriesCount:      45,
		AppliedCommandsCount: 18,
		UptimeSeconds:        3600,
	}

	var b strings.Builder
	AppendRaftMetrics(&b, status)
	out := b.String()

	expectedSubstrings := []string{
		`dock_radar_raft_is_leader{node_id="coord-1"} 1`,
		`dock_radar_raft_term{node_id="coord-1"} 4`,
		`dock_radar_raft_commit_index{node_id="coord-1"} 42`,
		`dock_radar_raft_applied_index{node_id="coord-1"} 42`,
		`dock_radar_raft_last_log_index{node_id="coord-1"} 45`,
		`dock_radar_raft_peers_count{node_id="coord-1"} 2`,
		`dock_radar_raft_quorum_size{node_id="coord-1"} 2`,
		`dock_radar_raft_fsm_applied_total{node_id="coord-1"} 18`,
		`dock_radar_raft_state{node_id="coord-1",state="leader"} 1`,
		`dock_radar_raft_state{node_id="coord-1",state="follower"} 0`,
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(out, sub) {
			t.Errorf("expected output to contain %q, but got:\n%s", sub, out)
		}
	}
}
