package api

import (
	"net/http"

	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/healing"
	"github.com/kLauncher1/dock-radar/internal/mesh"
	"github.com/kLauncher1/dock-radar/internal/metrics"
	"github.com/kLauncher1/dock-radar/internal/security"
	"github.com/kLauncher1/dock-radar/internal/system"
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
		version = "1.5.0"
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

	text := metrics.FormatMetricsWithAll(
		sysMetrics,
		dockerStatus,
		h.LogBuffer,
		h.AlertDispatcher,
		h.AuditLogger,
		meshSummary,
		meshNodes,
		healingStats,
		version,
	)

	_, _ = w.Write([]byte(text))
}
