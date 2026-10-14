package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/healing"
	"github.com/kLauncher1/dock-radar/internal/logs"
	"github.com/kLauncher1/dock-radar/internal/mesh"
	"github.com/kLauncher1/dock-radar/internal/system"
)

// FormatMetrics serializes system, docker, engine, alert, and audit telemetry into standard Prometheus text format.
func FormatMetrics(
	sys system.Metrics,
	dock docker.DaemonStatus,
	ringBuffer *logs.RingBuffer,
	alertDispatcher *alert.Dispatcher,
	auditLogger *audit.Logger,
	appVersion string,
) string {
	return FormatMetricsWithAll(sys, dock, ringBuffer, alertDispatcher, auditLogger, nil, nil, nil, appVersion)
}

// FormatMetricsWithMesh serializes system, docker, engine, alert, audit, and cluster mesh telemetry into standard Prometheus text format.
func FormatMetricsWithMesh(
	sys system.Metrics,
	dock docker.DaemonStatus,
	ringBuffer *logs.RingBuffer,
	alertDispatcher *alert.Dispatcher,
	auditLogger *audit.Logger,
	meshSummary *mesh.ClusterSummary,
	meshNodes []*mesh.Node,
	appVersion string,
) string {
	return FormatMetricsWithAll(sys, dock, ringBuffer, alertDispatcher, auditLogger, meshSummary, meshNodes, nil, appVersion)
}

// FormatMetricsWithAll serializes all telemetry including cluster mesh and autonomous self-healing stats.
func FormatMetricsWithAll(
	sys system.Metrics,
	dock docker.DaemonStatus,
	ringBuffer *logs.RingBuffer,
	alertDispatcher *alert.Dispatcher,
	auditLogger *audit.Logger,
	meshSummary *mesh.ClusterSummary,
	meshNodes []*mesh.Node,
	healingStats *healing.HealingStats,
	appVersion string,
) string {
	var b strings.Builder

	// 1. Build & Host Info
	b.WriteString("# HELP dock_radar_build_info Build and version metadata for dock-radar engine.\n")
	b.WriteString("# TYPE dock_radar_build_info gauge\n")
	b.WriteString(fmt.Sprintf(
		"dock_radar_build_info{arch=\"%s\",hostname=\"%s\",os=\"%s\",version=\"%s\"} 1\n\n",
		escapeLabel(sys.Arch),
		escapeLabel(sys.Hostname),
		escapeLabel(sys.OS),
		escapeLabel(appVersion),
	))

	// 2. Host Runtime Telemetry
	b.WriteString("# HELP dock_radar_host_uptime_seconds System uptime of dock-radar host in seconds.\n")
	b.WriteString("# TYPE dock_radar_host_uptime_seconds counter\n")
	b.WriteString(fmt.Sprintf("dock_radar_host_uptime_seconds %d\n\n", sys.UptimeSeconds))

	b.WriteString("# HELP dock_radar_host_cpu_cores Number of logical CPU cores available.\n")
	b.WriteString("# TYPE dock_radar_host_cpu_cores gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_host_cpu_cores %d\n\n", sys.NumCPU))

	b.WriteString("# HELP dock_radar_goroutines_active Number of active Go goroutines.\n")
	b.WriteString("# TYPE dock_radar_goroutines_active gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_goroutines_active %d\n\n", sys.NumGoroutine))

	allocBytes := uint64(sys.AllocMB * 1024 * 1024)
	b.WriteString("# HELP dock_radar_host_memory_alloc_bytes Heap memory currently allocated in bytes.\n")
	b.WriteString("# TYPE dock_radar_host_memory_alloc_bytes gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_host_memory_alloc_bytes %d\n\n", allocBytes))

	totalAllocBytes := uint64(sys.TotalAllocMB * 1024 * 1024)
	b.WriteString("# HELP dock_radar_host_memory_total_alloc_bytes Cumulative heap memory allocated in bytes.\n")
	b.WriteString("# TYPE dock_radar_host_memory_total_alloc_bytes counter\n")
	b.WriteString(fmt.Sprintf("dock_radar_host_memory_total_alloc_bytes %d\n\n", totalAllocBytes))

	sysBytes := uint64(sys.SysMB * 1024 * 1024)
	b.WriteString("# HELP dock_radar_host_memory_sys_bytes Total memory obtained from the OS in bytes.\n")
	b.WriteString("# TYPE dock_radar_host_memory_sys_bytes gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_host_memory_sys_bytes %d\n\n", sysBytes))

	b.WriteString("# HELP dock_radar_host_gc_cycles_total Total number of completed garbage collection cycles.\n")
	b.WriteString("# TYPE dock_radar_host_gc_cycles_total counter\n")
	b.WriteString(fmt.Sprintf("dock_radar_host_gc_cycles_total %d\n\n", sys.NumGC))

	// 3. Docker Daemon Telemetry
	daemonAvailable := 0
	if dock.Available {
		daemonAvailable = 1
	}
	b.WriteString("# HELP dock_radar_docker_daemon_available Docker daemon availability flag (1 = reachable, 0 = unreachable).\n")
	b.WriteString("# TYPE dock_radar_docker_daemon_available gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_docker_daemon_available %d\n\n", daemonAvailable))

	b.WriteString("# HELP dock_radar_containers_total Total count of Docker containers present on the host.\n")
	b.WriteString("# TYPE dock_radar_containers_total gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_containers_total %d\n\n", dock.TotalCount))

	b.WriteString("# HELP dock_radar_containers_running Count of currently running Docker containers.\n")
	b.WriteString("# TYPE dock_radar_containers_running gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_containers_running %d\n\n", dock.RunningCount))

	// 4. Per-Container Telemetry (if containers exist)
	if len(dock.Containers) > 0 {
		b.WriteString("# HELP dock_radar_container_state Current state breakdown per container.\n")
		b.WriteString("# TYPE dock_radar_container_state gauge\n")
		for _, c := range dock.Containers {
			cName := extractContainerName(c)
			b.WriteString(fmt.Sprintf(
				"dock_radar_container_state{id=\"%s\",image=\"%s\",name=\"%s\",state=\"%s\"} 1\n",
				escapeLabel(c.ID),
				escapeLabel(c.Image),
				escapeLabel(cName),
				escapeLabel(c.State),
			))
		}
		b.WriteString("\n")

		b.WriteString("# HELP dock_radar_container_running Running state boolean flag per container (1 = running, 0 = stopped).\n")
		b.WriteString("# TYPE dock_radar_container_running gauge\n")
		for _, c := range dock.Containers {
			cName := extractContainerName(c)
			isRunning := 0
			if strings.EqualFold(c.State, "running") {
				isRunning = 1
			}
			b.WriteString(fmt.Sprintf(
				"dock_radar_container_running{id=\"%s\",image=\"%s\",name=\"%s\"} %d\n",
				escapeLabel(c.ID),
				escapeLabel(c.Image),
				escapeLabel(cName),
				isRunning,
			))
		}
		b.WriteString("\n")
	}

	// 4b. Compose Stack Telemetry
	stacks := docker.ExtractComposeStacks(dock.Containers)
	b.WriteString("# HELP dock_radar_compose_stacks_total Total count of detected Docker Compose stacks.\n")
	b.WriteString("# TYPE dock_radar_compose_stacks_total gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_compose_stacks_total %d\n\n", len(stacks)))

	if len(stacks) > 0 {
		b.WriteString("# HELP dock_radar_compose_stack_services Number of services in Compose stack by health status.\n")
		b.WriteString("# TYPE dock_radar_compose_stack_services gauge\n")
		for _, stack := range stacks {
			b.WriteString(fmt.Sprintf("dock_radar_compose_stack_services{health=\"%s\",project=\"%s\",state=\"running\"} %d\n",
				escapeLabel(stack.Health), escapeLabel(stack.Project), stack.RunningServices))
			b.WriteString(fmt.Sprintf("dock_radar_compose_stack_services{health=\"%s\",project=\"%s\",state=\"total\"} %d\n",
				escapeLabel(stack.Health), escapeLabel(stack.Project), stack.TotalServices))
		}
		b.WriteString("\n")
	}

	// 5. Engine Telemetry: Ring Buffer
	ringEntries := 0
	ringBytes := 0
	if ringBuffer != nil {
		ringEntries = ringBuffer.Len()
		ringBytes = ringBuffer.EstimateMemoryBytes()
	}
	b.WriteString("# HELP dock_radar_ringbuffer_entries Number of log entries buffered in memory.\n")
	b.WriteString("# TYPE dock_radar_ringbuffer_entries gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_ringbuffer_entries %d\n\n", ringEntries))

	b.WriteString("# HELP dock_radar_ringbuffer_memory_bytes Estimated memory utilization of the log ring buffer.\n")
	b.WriteString("# TYPE dock_radar_ringbuffer_memory_bytes gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_ringbuffer_memory_bytes %d\n\n", ringBytes))

	// 6. Alert Events Telemetry
	alertCount := 0
	if alertDispatcher != nil {
		alertCount = len(alertDispatcher.RecentEvents(0))
	}
	b.WriteString("# HELP dock_radar_alert_events_total Total alert incidents recorded in memory.\n")
	b.WriteString("# TYPE dock_radar_alert_events_total gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_alert_events_total %d\n\n", alertCount))

	// 7. Audit Events Telemetry
	var auditCount int64 = 0
	if auditLogger != nil {
		auditCount = auditLogger.TotalCount()
	}
	b.WriteString("# HELP dock_radar_audit_events_total Cumulative audit log events recorded by dock-radar.\n")
	b.WriteString("# TYPE dock_radar_audit_events_total counter\n")
	b.WriteString(fmt.Sprintf("dock_radar_audit_events_total %d\n\n", auditCount))

	// 8. Cluster Mesh Telemetry
	if meshSummary != nil {
		b.WriteString("# HELP dock_radar_mesh_nodes_total Total number of registered cluster nodes in the mesh.\n")
		b.WriteString("# TYPE dock_radar_mesh_nodes_total gauge\n")
		b.WriteString(fmt.Sprintf("dock_radar_mesh_nodes_total %d\n\n", meshSummary.TotalNodes))

		b.WriteString("# HELP dock_radar_mesh_nodes_online Number of healthy online cluster nodes.\n")
		b.WriteString("# TYPE dock_radar_mesh_nodes_online gauge\n")
		b.WriteString(fmt.Sprintf("dock_radar_mesh_nodes_online %d\n\n", meshSummary.OnlineNodes))

		b.WriteString("# HELP dock_radar_mesh_nodes_offline Number of offline or unreachable cluster nodes.\n")
		b.WriteString("# TYPE dock_radar_mesh_nodes_offline gauge\n")
		b.WriteString(fmt.Sprintf("dock_radar_mesh_nodes_offline %d\n\n", meshSummary.OfflineNodes))

		b.WriteString("# HELP dock_radar_mesh_containers_total Total container count across all mesh cluster nodes.\n")
		b.WriteString("# TYPE dock_radar_mesh_containers_total gauge\n")
		b.WriteString(fmt.Sprintf("dock_radar_mesh_containers_total %d\n\n", meshSummary.TotalContainers))

		b.WriteString("# HELP dock_radar_mesh_containers_running Running container count across all mesh cluster nodes.\n")
		b.WriteString("# TYPE dock_radar_mesh_containers_running gauge\n")
		b.WriteString(fmt.Sprintf("dock_radar_mesh_containers_running %d\n\n", meshSummary.RunningContainers))

		b.WriteString("# HELP dock_radar_mesh_aggregate_cpu_percent Average CPU utilization across active cluster nodes.\n")
		b.WriteString("# TYPE dock_radar_mesh_aggregate_cpu_percent gauge\n")
		b.WriteString(fmt.Sprintf("dock_radar_mesh_aggregate_cpu_percent %.2f\n\n", meshSummary.AggregateCPUPercent))

		b.WriteString("# HELP dock_radar_mesh_aggregate_memory_used_bytes Total memory used across active cluster nodes.\n")
		b.WriteString("# TYPE dock_radar_mesh_aggregate_memory_used_bytes gauge\n")
		b.WriteString(fmt.Sprintf("dock_radar_mesh_aggregate_memory_used_bytes %d\n\n", meshSummary.AggregateMemoryUsedBytes))

		if len(meshNodes) > 0 {
			b.WriteString("# HELP dock_radar_mesh_node_status Status per cluster node (1 = online, 0 = offline/degraded).\n")
			b.WriteString("# TYPE dock_radar_mesh_node_status gauge\n")
			for _, n := range meshNodes {
				isOnline := 0
				if n.Status == mesh.NodeStatusOnline {
					isOnline = 1
				}
				b.WriteString(fmt.Sprintf(
					"dock_radar_mesh_node_status{address=\"%s\",id=\"%s\",name=\"%s\",status=\"%s\"} %d\n",
					escapeLabel(n.Address),
					escapeLabel(n.ID),
					escapeLabel(n.Name),
					escapeLabel(string(n.Status)),
					isOnline,
				))
			}
			b.WriteString("\n")

			b.WriteString("# HELP dock_radar_mesh_node_latency_ms Round-trip ping latency in milliseconds.\n")
			b.WriteString("# TYPE dock_radar_mesh_node_latency_ms gauge\n")
			for _, n := range meshNodes {
				b.WriteString(fmt.Sprintf(
					"dock_radar_mesh_node_latency_ms{address=\"%s\",id=\"%s\",name=\"%s\"} %d\n",
					escapeLabel(n.Address),
					escapeLabel(n.ID),
					escapeLabel(n.Name),
					n.LatencyMs,
				))
			}
			b.WriteString("\n")
		}
	}

	// 9. Autonomous Self-Healing Telemetry
	if healingStats != nil {
		healingEnabled := 0
		if healingStats.Enabled {
			healingEnabled = 1
		}
		b.WriteString("# HELP dock_radar_healing_enabled Self-healing engine operational state (1 = active, 0 = disabled).\n")
		b.WriteString("# TYPE dock_radar_healing_enabled gauge\n")
		b.WriteString(fmt.Sprintf("dock_radar_healing_enabled %d\n\n", healingEnabled))

		b.WriteString("# HELP dock_radar_healing_remediations_total Total successful container remediations performed.\n")
		b.WriteString("# TYPE dock_radar_healing_remediations_total counter\n")
		b.WriteString(fmt.Sprintf("dock_radar_healing_remediations_total %d\n\n", healingStats.TotalRemediated))

		b.WriteString("# HELP dock_radar_healing_quarantined_containers Number of containers currently circuit-broken and quarantined.\n")
		b.WriteString("# TYPE dock_radar_healing_quarantined_containers gauge\n")
		b.WriteString(fmt.Sprintf("dock_radar_healing_quarantined_containers %d\n\n", len(healingStats.QuarantinedContainers)))

		b.WriteString("# HELP dock_radar_healing_active_backoffs Number of containers currently in exponential backoff delay.\n")
		b.WriteString("# TYPE dock_radar_healing_active_backoffs gauge\n")
		b.WriteString(fmt.Sprintf("dock_radar_healing_active_backoffs %d\n\n", healingStats.ActiveBackoffs))
	}

	return b.String()
}

func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func extractContainerName(c docker.ContainerSummary) string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	if len(c.ID) > 12 {
		return c.ID[:12]
	}
	return c.ID
}
