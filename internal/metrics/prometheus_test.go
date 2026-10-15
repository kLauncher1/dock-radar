package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/anomaly"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/healing"
	"github.com/kLauncher1/dock-radar/internal/logs"
	"github.com/kLauncher1/dock-radar/internal/mesh"
	"github.com/kLauncher1/dock-radar/internal/system"
)

func TestFormatMetrics_FullPayload(t *testing.T) {
	sys := system.Metrics{
		Hostname:      "test-box\"\\special",
		OS:            "linux",
		Arch:          "amd64",
		NumCPU:        8,
		NumGoroutine:  35,
		AllocMB:       12.5,
		TotalAllocMB:  50.0,
		SysMB:         30.0,
		NumGC:         14,
		UptimeSeconds: 3600,
	}

	dock := docker.DaemonStatus{
		Available:    true,
		TotalCount:   2,
		RunningCount: 1,
		Containers: []docker.ContainerSummary{
			{
				ID:    "c_web_123456789",
				Names: []string{"/nginx-gateway"},
				Image: "nginx:latest",
				State: "running",
			},
			{
				ID:    "c_db_987654321",
				Names: []string{"/postgres-db"},
				Image: "postgres:15-alpine",
				State: "exited",
			},
		},
	}

	rb := logs.NewRingBuffer(10)
	rb.Append(logs.LogEntry{ID: "c_web_123456789", Message: "hello log line"})

	cfgStore := alert.NewConfigStore(alert.DefaultConfig())
	disp := alert.NewDispatcher(cfgStore)
	disp.RecordEvent(alert.Event{
		ID:        "evt-1",
		Timestamp: time.Now().UTC(),
		Level:     alert.LevelCritical,
		Source:    "container",
		EventType: "crash",
		Message:   "Container crashed",
	})

	auditLog := audit.NewLogger(10)
	auditLog.Log(audit.AuditEvent{
		Action: "batch_restart_all",
		Target: "all",
	})
	auditLog.Log(audit.AuditEvent{
		Action: "batch_prune",
		Target: "unused",
	})

	output := FormatMetrics(sys, dock, rb, disp, auditLog, "1.1.0")

	// Verification 1: Build Info & Escaping
	if !strings.Contains(output, `dock_radar_build_info{arch="amd64",hostname="test-box\"\\special",os="linux",version="1.1.0"} 1`) {
		t.Errorf("missing or misformatted build_info metric:\n%s", output)
	}

	// Verification 2: Host Telemetry
	expectedHostLines := []string{
		"dock_radar_host_uptime_seconds 3600",
		"dock_radar_host_cpu_cores 8",
		"dock_radar_goroutines_active 35",
		"dock_radar_host_gc_cycles_total 14",
	}
	for _, expected := range expectedHostLines {
		if !strings.Contains(output, expected) {
			t.Errorf("missing expected line: %s", expected)
		}
	}

	// Verification 3: Container Telemetry
	expectedContainerLines := []string{
		"dock_radar_docker_daemon_available 1",
		"dock_radar_containers_total 2",
		"dock_radar_containers_running 1",
		`dock_radar_container_state{id="c_web_123456789",image="nginx:latest",name="nginx-gateway",state="running"} 1`,
		`dock_radar_container_state{id="c_db_987654321",image="postgres:15-alpine",name="postgres-db",state="exited"} 1`,
		`dock_radar_container_running{id="c_web_123456789",image="nginx:latest",name="nginx-gateway"} 1`,
		`dock_radar_container_running{id="c_db_987654321",image="postgres:15-alpine",name="postgres-db"} 0`,
	}
	for _, expected := range expectedContainerLines {
		if !strings.Contains(output, expected) {
			t.Errorf("missing container line: %s", expected)
		}
	}

	// Verification 4: Engine, Alerts & Audit Telemetry
	expectedEngineLines := []string{
		"dock_radar_ringbuffer_entries 1",
		"dock_radar_alert_events_total 1",
		"dock_radar_audit_events_total 2",
	}
	for _, expected := range expectedEngineLines {
		if !strings.Contains(output, expected) {
			t.Errorf("missing engine line: %s", expected)
		}
	}

	// Verification 5: HELP and TYPE statements
	expectedHelpStatements := []string{
		"# HELP dock_radar_build_info",
		"# TYPE dock_radar_build_info gauge",
		"# HELP dock_radar_host_uptime_seconds",
		"# TYPE dock_radar_host_uptime_seconds counter",
		"# HELP dock_radar_audit_events_total",
		"# TYPE dock_radar_audit_events_total counter",
	}
	for _, expected := range expectedHelpStatements {
		if !strings.Contains(output, expected) {
			t.Errorf("missing HELP/TYPE: %s", expected)
		}
	}
}

func TestFormatMetrics_OfflineDaemonAndNilComponents(t *testing.T) {
	sys := system.Metrics{
		Hostname:      "solo-node",
		OS:            "windows",
		Arch:          "amd64",
		NumCPU:        4,
		NumGoroutine:  10,
		AllocMB:       5.0,
		TotalAllocMB:  10.0,
		SysMB:         15.0,
		NumGC:         2,
		UptimeSeconds: 120,
	}

	dock := docker.DaemonStatus{
		Available:    false,
		TotalCount:   0,
		RunningCount: 0,
		Containers:   []docker.ContainerSummary{},
	}

	output := FormatMetrics(sys, dock, nil, nil, nil, "1.1.0")

	if !strings.Contains(output, "dock_radar_docker_daemon_available 0") {
		t.Errorf("expected daemon available to be 0 for offline docker")
	}
	if !strings.Contains(output, "dock_radar_ringbuffer_entries 0") {
		t.Errorf("expected ringbuffer entries to be 0 when nil")
	}
	if !strings.Contains(output, "dock_radar_alert_events_total 0") {
		t.Errorf("expected alert events to be 0 when nil")
	}
	if !strings.Contains(output, "dock_radar_audit_events_total 0") {
		t.Errorf("expected audit events to be 0 when nil")
	}
	if strings.Contains(output, "dock_radar_container_state") {
		t.Errorf("expected no container_state lines when container list is empty")
	}
}

func TestEscapeLabel(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{`normal`, `normal`},
		{`with"quote`, `with\"quote`},
		{`with\slash`, `with\\slash`},
		{"with\nnewline", `with\nnewline`},
		{`complex"\\` + "\n", `complex\"\\\\` + `\n`},
	}

	for _, c := range cases {
		actual := escapeLabel(c.input)
		if actual != c.expected {
			t.Errorf("for input %q: expected %q, got %q", c.input, c.expected, actual)
		}
	}
}

func TestFormatMetricsWithMesh(t *testing.T) {
	sys := system.Metrics{
		Hostname: "mesh-host",
		OS:       "linux",
		Arch:     "amd64",
	}
	dock := docker.DaemonStatus{Available: true}

	summary := &mesh.ClusterSummary{
		TotalNodes:               3,
		OnlineNodes:              2,
		OfflineNodes:             1,
		TotalContainers:          8,
		RunningContainers:        5,
		AggregateCPUPercent:      25.5,
		AggregateMemoryUsedBytes: 2048,
	}

	nodes := []*mesh.Node{
		{
			ID:        "node-alpha",
			Name:      "Node Alpha",
			Address:   "http://10.0.0.1:9080",
			Status:    mesh.NodeStatusOnline,
			LatencyMs: 4,
		},
		{
			ID:        "node-beta",
			Name:      "Node Beta",
			Address:   "http://10.0.0.2:9080",
			Status:    mesh.NodeStatusOffline,
			LatencyMs: 0,
		},
	}

	output := FormatMetricsWithMesh(sys, dock, nil, nil, nil, summary, nodes, "1.2.0")

	if !strings.Contains(output, "dock_radar_mesh_nodes_total 3") {
		t.Errorf("missing mesh nodes total in output:\n%s", output)
	}
	if !strings.Contains(output, "dock_radar_mesh_nodes_online 2") {
		t.Errorf("missing mesh nodes online in output")
	}
	if !strings.Contains(output, "dock_radar_mesh_nodes_offline 1") {
		t.Errorf("missing mesh nodes offline in output")
	}
	if !strings.Contains(output, "dock_radar_mesh_containers_total 8") {
		t.Errorf("missing mesh containers total in output")
	}
	if !strings.Contains(output, "dock_radar_mesh_containers_running 5") {
		t.Errorf("missing mesh containers running in output")
	}
	if !strings.Contains(output, "dock_radar_mesh_aggregate_cpu_percent 25.50") {
		t.Errorf("missing mesh aggregate cpu in output")
	}
	if !strings.Contains(output, `dock_radar_mesh_node_status{address="http://10.0.0.1:9080",id="node-alpha",name="Node Alpha",status="online"} 1`) {
		t.Errorf("missing node alpha status in output")
	}
	if !strings.Contains(output, `dock_radar_mesh_node_status{address="http://10.0.0.2:9080",id="node-beta",name="Node Beta",status="offline"} 0`) {
		t.Errorf("missing node beta status in output")
	}
	if !strings.Contains(output, `dock_radar_mesh_node_latency_ms{address="http://10.0.0.1:9080",id="node-alpha",name="Node Alpha"} 4`) {
		t.Errorf("missing node alpha latency in output")
	}
}

func TestFormatMetrics_ComposeStacks(t *testing.T) {
	sys := system.Metrics{
		OS:   "linux",
		Arch: "amd64",
	}

	dock := docker.DaemonStatus{
		Available:    true,
		TotalCount:   2,
		RunningCount: 2,
		Containers: []docker.ContainerSummary{
			{
				ID:    "c_web_1",
				Names: []string{"/ecommerce-web-1"},
				Image: "frontend:latest",
				State: "running",
				Labels: map[string]string{
					"com.docker.compose.project": "ecommerce",
					"com.docker.compose.service": "web",
				},
			},
			{
				ID:    "c_db_1",
				Names: []string{"/ecommerce-db-1"},
				Image: "postgres:16-alpine",
				State: "running",
				Labels: map[string]string{
					"com.docker.compose.project": "ecommerce",
					"com.docker.compose.service": "db",
				},
			},
		},
	}

	output := FormatMetrics(sys, dock, nil, nil, nil, "1.4.0")

	if !strings.Contains(output, "dock_radar_compose_stacks_total 1") {
		t.Errorf("missing compose stacks total in output:\n%s", output)
	}
	if !strings.Contains(output, `dock_radar_compose_stack_services{health="healthy",project="ecommerce",state="running"} 2`) {
		t.Errorf("missing compose stack running services in output")
	}
	if !strings.Contains(output, `dock_radar_compose_stack_services{health="healthy",project="ecommerce",state="total"} 2`) {
		t.Errorf("missing compose stack total services in output")
	}
}

func TestFormatMetrics_SelfHealing(t *testing.T) {
	sys := system.Metrics{OS: "linux", Arch: "amd64", Hostname: "node-1"}
	dock := docker.DaemonStatus{Available: true}
	stats := &healing.HealingStats{
		Enabled:          true,
		TotalRemediated:  12,
		TotalQuarantined: 2,
		ActiveBackoffs:   1,
		QuarantinedContainers: []healing.QuarantinedInfo{
			{ContainerID: "c1", ContainerName: "flapping-worker"},
			{ContainerID: "c2", ContainerName: "bad-service"},
		},
	}

	output := FormatMetricsWithAll(sys, dock, nil, nil, nil, nil, nil, stats, "1.5.0")

	if !strings.Contains(output, "dock_radar_healing_enabled 1") {
		t.Errorf("missing dock_radar_healing_enabled in output:\n%s", output)
	}
	if !strings.Contains(output, "dock_radar_healing_remediations_total 12") {
		t.Errorf("missing dock_radar_healing_remediations_total in output:\n%s", output)
	}
	if !strings.Contains(output, "dock_radar_healing_quarantined_containers 2") {
		t.Errorf("missing dock_radar_healing_quarantined_containers in output:\n%s", output)
	}
	if !strings.Contains(output, "dock_radar_healing_active_backoffs 1") {
		t.Errorf("missing dock_radar_healing_active_backoffs in output:\n%s", output)
	}
}

func TestFormatMetrics_AnomalyDetection(t *testing.T) {
	sys := system.Metrics{OS: "linux", Arch: "amd64", Hostname: "node-1"}
	dock := docker.DaemonStatus{Available: true}
	summary := &anomaly.AnomalySummary{
		MonitoredContainers: 5,
		CriticalCount:       1,
		WarningCount:        2,
		StableCount:         2,
	}
	preds := []anomaly.TrendPrediction{
		{
			ContainerID:      "c-leaky",
			ContainerName:    "leaky-worker",
			Category:         anomaly.ExhaustionCritical,
			SlopeBytesPerSec: 1048576.0,
			SecondsToOOM:     42.5,
		},
	}

	output := FormatMetricsWithAnomaly(sys, dock, nil, nil, nil, nil, nil, nil, summary, preds, "1.6.0")

	if !strings.Contains(output, "dock_radar_anomaly_containers_monitored 5") {
		t.Errorf("missing dock_radar_anomaly_containers_monitored in output:\n%s", output)
	}
	if !strings.Contains(output, "dock_radar_anomaly_critical_imminent_total 1") {
		t.Errorf("missing dock_radar_anomaly_critical_imminent_total in output:\n%s", output)
	}
	if !strings.Contains(output, "dock_radar_anomaly_warning_total 2") {
		t.Errorf("missing dock_radar_anomaly_warning_total in output:\n%s", output)
	}
	if !strings.Contains(output, `dock_radar_anomaly_memory_growth_rate_bytes_per_sec{category="critical_oom_imminent",container="leaky-worker",id="c-leaky"} 1048576.00`) {
		t.Errorf("missing memory growth rate gauge in output:\n%s", output)
	}
	if !strings.Contains(output, `dock_radar_anomaly_predicted_oom_seconds{category="critical_oom_imminent",container="leaky-worker",id="c-leaky"} 42.50`) {
		t.Errorf("missing predicted oom seconds gauge in output:\n%s", output)
	}
}

func TestFormatMetrics_MeshDiscoveryAndGossip(t *testing.T) {
	sys := system.Metrics{OS: "linux", Arch: "amd64", Hostname: "node-1"}
	dock := docker.DaemonStatus{Available: true}

	discStatus := &mesh.DiscoveryStatus{
		Enabled:         true,
		PeersCount:      3,
		BeaconsSent:     42,
		BeaconsReceived: 108,
	}

	gossipSummary := &mesh.GossipSummary{
		Incarnation:    7,
		AliveMembers:   3,
		SuspectMembers: 1,
		DeadMembers:    0,
		MessagesSent:   250,
		MessagesRecv:   248,
	}

	output := FormatMetricsFull(sys, dock, nil, nil, nil, nil, nil, nil, nil, nil, discStatus, gossipSummary, nil, "1.7.0")

	expectedGauges := []string{
		"dock_radar_mesh_discovery_enabled 1",
		"dock_radar_mesh_discovery_peers_detected_total 3",
		"dock_radar_mesh_discovery_beacons_sent_total 42",
		"dock_radar_mesh_discovery_beacons_received_total 108",
		"dock_radar_mesh_gossip_incarnation 7",
		`dock_radar_mesh_gossip_members{state="alive"} 3`,
		`dock_radar_mesh_gossip_members{state="suspect"} 1`,
		`dock_radar_mesh_gossip_members{state="dead"} 0`,
		"dock_radar_mesh_gossip_messages_sent_total 250",
		"dock_radar_mesh_gossip_messages_received_total 248",
	}

	for _, g := range expectedGauges {
		if !strings.Contains(output, g) {
			t.Errorf("expected Prometheus output to contain %q, but was missing:\n%s", g, output)
		}
	}
}



