package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/raft"
)

// AppendRaftMetrics formats High-Availability Raft consensus telemetry into standard Prometheus exposition format.
func AppendRaftMetrics(builder *strings.Builder, status *raft.RaftStatus) {
	if status == nil {
		return
	}

	nodeLabel := escapeLabel(status.NodeID)

	builder.WriteString("# HELP dock_radar_raft_is_leader Indicator of whether the local node is the cluster Raft leader (1 if leader, 0 otherwise)\n")
	builder.WriteString("# TYPE dock_radar_raft_is_leader gauge\n")
	isLeaderVal := 0
	if status.IsLeader {
		isLeaderVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_raft_is_leader{node_id=\"%s\"} %d\n", nodeLabel, isLeaderVal)

	builder.WriteString("# HELP dock_radar_raft_term Current consensus term of the local node\n")
	builder.WriteString("# TYPE dock_radar_raft_term gauge\n")
	fmt.Fprintf(builder, "dock_radar_raft_term{node_id=\"%s\"} %d\n", nodeLabel, status.Term)

	builder.WriteString("# HELP dock_radar_raft_commit_index Index of highest log entry known to be committed\n")
	builder.WriteString("# TYPE dock_radar_raft_commit_index gauge\n")
	fmt.Fprintf(builder, "dock_radar_raft_commit_index{node_id=\"%s\"} %d\n", nodeLabel, status.CommitIndex)

	builder.WriteString("# HELP dock_radar_raft_applied_index Index of highest log entry applied to replicated state machine\n")
	builder.WriteString("# TYPE dock_radar_raft_applied_index gauge\n")
	fmt.Fprintf(builder, "dock_radar_raft_applied_index{node_id=\"%s\"} %d\n", nodeLabel, status.LastApplied)

	builder.WriteString("# HELP dock_radar_raft_last_log_index Index of the highest log entry stored locally\n")
	builder.WriteString("# TYPE dock_radar_raft_last_log_index gauge\n")
	fmt.Fprintf(builder, "dock_radar_raft_last_log_index{node_id=\"%s\"} %d\n", nodeLabel, status.LastLogIndex)

	builder.WriteString("# HELP dock_radar_raft_peers_count Number of configured Raft cluster peer nodes\n")
	builder.WriteString("# TYPE dock_radar_raft_peers_count gauge\n")
	fmt.Fprintf(builder, "dock_radar_raft_peers_count{node_id=\"%s\"} %d\n", nodeLabel, status.PeerCount)

	builder.WriteString("# HELP dock_radar_raft_quorum_size Number of nodes required to satisfy cluster majority quorum\n")
	builder.WriteString("# TYPE dock_radar_raft_quorum_size gauge\n")
	fmt.Fprintf(builder, "dock_radar_raft_quorum_size{node_id=\"%s\"} %d\n", nodeLabel, status.QuorumSize)

	builder.WriteString("# HELP dock_radar_raft_fsm_applied_total Cumulative state machine commands applied\n")
	builder.WriteString("# TYPE dock_radar_raft_fsm_applied_total counter\n")
	fmt.Fprintf(builder, "dock_radar_raft_fsm_applied_total{node_id=\"%s\"} %d\n", nodeLabel, status.AppliedCommandsCount)

	builder.WriteString("# HELP dock_radar_raft_state Current Raft operational state (1 for active state, 0 otherwise)\n")
	builder.WriteString("# TYPE dock_radar_raft_state gauge\n")
	for _, s := range []string{"leader", "follower", "candidate"} {
		v := 0
		if status.State == s {
			v = 1
		}
		fmt.Fprintf(builder, "dock_radar_raft_state{node_id=\"%s\",state=\"%s\"} %d\n", nodeLabel, s, v)
	}
	builder.WriteString("\n")
}
