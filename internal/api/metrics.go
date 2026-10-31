package api

import (
	"net/http"

	"github.com/kLauncher1/dock-radar/internal/anomaly"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/ebpf"
	"github.com/kLauncher1/dock-radar/internal/federation"
	"github.com/kLauncher1/dock-radar/internal/firewall"
	"github.com/kLauncher1/dock-radar/internal/gitops"
	"github.com/kLauncher1/dock-radar/internal/healing"
	"github.com/kLauncher1/dock-radar/internal/mesh"
	"github.com/kLauncher1/dock-radar/internal/metrics"
	"github.com/kLauncher1/dock-radar/internal/raft"
	"github.com/kLauncher1/dock-radar/internal/ratelimit"
	"github.com/kLauncher1/dock-radar/internal/rolling"
	"github.com/kLauncher1/dock-radar/internal/scanner"
	"github.com/kLauncher1/dock-radar/internal/security"
	"github.com/kLauncher1/dock-radar/internal/storage"
	"github.com/kLauncher1/dock-radar/internal/system"
	"github.com/kLauncher1/dock-radar/internal/wireguard"
)

func (h *HandlerConfig) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	sysMetrics := system.CollectTelemetry()

	var dockerStatus docker.DaemonStatus
	if h.DockerClient != nil {
		dockerStatus = h.DockerClient.InspectContainers()
	}

	version := h.AppVersion
	if version == "" {
		version = "1.6.0"
	}

	var meshSummary *mesh.ClusterSummary
	var meshNodes []*mesh.Node
	if h.MeshRegistry != nil {
		s := h.MeshRegistry.ClusterSummary()
		meshSummary = &s
		meshNodes = h.MeshRegistry.List()
	}

	var healingStats *healing.HealingStats
	if h.HealingEngine != nil {
		st := h.HealingEngine.Stats()
		healingStats = &st
	}

	var anomalySummary *anomaly.AnomalySummary
	var anomalyPreds []anomaly.TrendPrediction
	if h.AnomalyDetector != nil {
		summ := h.AnomalyDetector.GetSummary()
		anomalySummary = &summ
		anomalyPreds = h.AnomalyDetector.GetPredictions()
	}

	var discStatus *mesh.DiscoveryStatus
	if h.MeshDiscovery != nil {
		st := h.MeshDiscovery.Status()
		discStatus = &st
	}

	var gossipSummary *mesh.GossipSummary
	var gossipMembers []mesh.GossipMember
	if h.MeshGossip != nil {
		summ := h.MeshGossip.Summary()
		gossipSummary = &summ
		gossipMembers = h.MeshGossip.Members()
	}

	var rollingStats *rolling.RollingStats
	if h.RollingEngine != nil {
		st := h.RollingEngine.Stats()
		rollingStats = &st
	}

	var storageStatus *storage.StorageStatus
	if h.StorageManager != nil {
		st := h.StorageManager.Status()
		storageStatus = &st
	}

	var ebpfStatus *ebpf.EBPFStatus
	if h.EBPFEngine != nil {
		st := h.EBPFEngine.Status()
		ebpfStatus = &st
	}

	var fedStatus *federation.FederationStatus
	if h.FederationEngine != nil {
		st := h.FederationEngine.GetStatus()
		fedStatus = &st
	}

	var scannerStatus *scanner.ScannerStatus
	if h.ScannerEngine != nil {
		st := h.ScannerEngine.GetStatus()
		scannerStatus = &st
	}

	var rateLimitStatus *ratelimit.LimiterStatus
	if h.RateLimitEngine != nil {
		st := h.RateLimitEngine.Status()
		rateLimitStatus = &st
	}

	var firewallStatus *firewall.FirewallStatus
	if h.FirewallEngine != nil {
		st := h.FirewallEngine.Status()
		firewallStatus = &st
	}

	var gitopsStatus *gitops.GitOpsStatus
	if h.GitOpsEngine != nil {
		st := h.GitOpsEngine.Status()
		gitopsStatus = &st
	}

	var raftStatus *raft.RaftStatus
	if h.RaftEngine != nil {
		st := h.RaftEngine.Status()
		raftStatus = &st
	}

	var wgStatus *wireguard.WireGuardStatus
	if h.WireGuardEngine != nil {
		st := h.WireGuardEngine.Status()
		wgStatus = &st
	}

	text := metrics.FormatMetricsAll(
		sysMetrics,
		dockerStatus,
		h.LogBuffer,
		h.AlertDispatcher,
		h.AuditLogger,
		meshSummary,
		meshNodes,
		healingStats,
		anomalySummary,
		anomalyPreds,
		discStatus,
		gossipSummary,
		gossipMembers,
		rollingStats,
		storageStatus,
		ebpfStatus,
		fedStatus,
		scannerStatus,
		rateLimitStatus,
		firewallStatus,
		gitopsStatus,
		raftStatus,
		wgStatus,
		version,
	)

	_, _ = w.Write([]byte(text))
}
