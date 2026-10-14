package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/logs"
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
