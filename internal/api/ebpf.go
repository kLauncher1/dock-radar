package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/ebpf"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// EBPFStatusResponse encapsulates runtime telemetry for kernel probes.
type EBPFStatusResponse struct {
	Status      ebpf.EBPFStatus `json:"status"`
	GeneratedAt time.Time       `json:"generated_at"`
}

// EBPFFlowsResponse provides queried active socket flows.
type EBPFFlowsResponse struct {
	Flows       []ebpf.SocketFlow `json:"flows"`
	TotalCount  int               `json:"total_count"`
	GeneratedAt time.Time         `json:"generated_at"`
}

// EBPFSecurityEventsResponse provides recent security alerts.
type EBPFSecurityEventsResponse struct {
	Events      []ebpf.SecurityAlert `json:"events"`
	TotalCount  int                  `json:"total_count"`
	GeneratedAt time.Time            `json:"generated_at"`
}

// EBPFSecurityRulesResponse wraps configured security threat rules.
type EBPFSecurityRulesResponse struct {
	Rules      []ebpf.SecurityRule `json:"rules"`
	TotalCount int                 `json:"total_count"`
}

// EBPFActionResponse delivers feedback for administrative mutations.
type EBPFActionResponse struct {
	Success   bool      `json:"success"`
	Action    string    `json:"action"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// handleEBPFStatus returns current probe mode, tracked flows, and resource overhead.
func (h *HandlerConfig) handleEBPFStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.EBPFEngine == nil {
		writeJSONResponse(w, http.StatusOK, EBPFStatusResponse{
			Status:      ebpf.EBPFStatus{Enabled: false, Mode: ebpf.ProbeModeSynthetic},
			GeneratedAt: time.Now().UTC(),
		})
		return
	}

	status := h.EBPFEngine.Status()
	writeJSONResponse(w, http.StatusOK, EBPFStatusResponse{
		Status:      status,
		GeneratedAt: time.Now().UTC(),
	})
}

// handleEBPFFlows returns active container socket flows with optional filtering.
func (h *HandlerConfig) handleEBPFFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.EBPFEngine == nil {
		writeJSONResponse(w, http.StatusOK, EBPFFlowsResponse{
			Flows:       []ebpf.SocketFlow{},
			TotalCount:  0,
			GeneratedAt: time.Now().UTC(),
		})
		return
	}

	filter := ebpf.FlowFilter{
		ContainerID: r.URL.Query().Get("container_id"),
		State:       r.URL.Query().Get("state"),
		Protocol:    r.URL.Query().Get("protocol"),
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			filter.Limit = l
		}
	}

	flows := h.EBPFEngine.Flows(filter)
	writeJSONResponse(w, http.StatusOK, EBPFFlowsResponse{
		Flows:       flows,
		TotalCount:  len(flows),
		GeneratedAt: time.Now().UTC(),
	})
}

// handleEBPFSecurityEvents returns recent kernel security anomaly alerts.
func (h *HandlerConfig) handleEBPFSecurityEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.EBPFEngine == nil {
		writeJSONResponse(w, http.StatusOK, EBPFSecurityEventsResponse{
			Events:      []ebpf.SecurityAlert{},
			TotalCount:  0,
			GeneratedAt: time.Now().UTC(),
		})
		return
	}

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 500 {
			limit = l
		}
	}

	severity := r.URL.Query().Get("severity")
	containerID := r.URL.Query().Get("container_id")

	events := h.EBPFEngine.Security().RecentAlerts(limit, severity, containerID)
	writeJSONResponse(w, http.StatusOK, EBPFSecurityEventsResponse{
		Events:      events,
		TotalCount:  len(events),
		GeneratedAt: time.Now().UTC(),
	})
}

// handleEBPFSecurityRules manages reading and updating threat detection rules.
func (h *HandlerConfig) handleEBPFSecurityRules(w http.ResponseWriter, r *http.Request) {
	if h.EBPFEngine == nil {
		http.Error(w, "eBPF engine not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		rules := h.EBPFEngine.Security().GetRules()
		writeJSONResponse(w, http.StatusOK, EBPFSecurityRulesResponse{
			Rules:      rules,
			TotalCount: len(rules),
		})

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}

		// Support quick toggle query: ?toggle=rule_id&enabled=true/false
		toggleID := r.URL.Query().Get("toggle")
		if toggleID != "" {
			enabled := r.URL.Query().Get("enabled") != "false"
			if err := h.EBPFEngine.Security().ToggleRule(toggleID, enabled); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if h.AuditLogger != nil {
				h.AuditLogger.Log(audit.AuditEvent{
					Action:  "ebpf_rule_toggle",
					Target:  toggleID,
					Details: map[string]any{"enabled": enabled},
				})
			}
			writeJSONResponse(w, http.StatusOK, EBPFActionResponse{
				Success:   true,
				Action:    "toggle_rule",
				Message:   "Rule updated successfully",
				Timestamp: time.Now().UTC(),
			})
			return
		}

		// Full rules replacement from JSON body
		body, err := io.ReadAll(io.LimitReader(r.Body, 128*1024))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}

		var payload struct {
			Rules []ebpf.SecurityRule `json:"rules"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "invalid JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := h.EBPFEngine.Security().UpdateRules(payload.Rules); err != nil {
			http.Error(w, "invalid rules: "+err.Error(), http.StatusBadRequest)
			return
		}

		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Action:  "ebpf_rules_update",
				Target:  "security_engine",
				Details: map[string]any{"count": len(payload.Rules)},
			})
		}

		writeJSONResponse(w, http.StatusOK, EBPFActionResponse{
			Success:   true,
			Action:    "update_rules",
			Message:   "Security rules updated successfully",
			Timestamp: time.Now().UTC(),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleEBPFReset clears active socket flows and alerts.
func (h *HandlerConfig) handleEBPFReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if h.EBPFEngine == nil {
		http.Error(w, "eBPF engine not initialized", http.StatusServiceUnavailable)
		return
	}

	h.EBPFEngine.Reset()

	if h.AuditLogger != nil {
		h.AuditLogger.Log(audit.AuditEvent{
			Action:  "ebpf_reset",
			Target:  "telemetry_engine",
			Details: map[string]any{"timestamp": time.Now().UTC()},
		})
	}

	writeJSONResponse(w, http.StatusOK, EBPFActionResponse{
		Success:   true,
		Action:    "reset",
		Message:   "eBPF flows and security alerts reset successfully",
		Timestamp: time.Now().UTC(),
	})
}

// handleEBPFTriggerTest creates a simulated anomaly event to verify alerting and dashboard reactions.
func (h *HandlerConfig) handleEBPFTriggerTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if h.EBPFEngine == nil {
		http.Error(w, "eBPF engine not initialized", http.StatusServiceUnavailable)
		return
	}

	cID := r.URL.Query().Get("container_id")
	if cID == "" {
		cID = "test-container"
	}
	cName := r.URL.Query().Get("container_name")
	if cName == "" {
		cName = "sample-worker"
	}

	testEvent := ebpf.SyscallEvent{
		ID:            "test-evt",
		Timestamp:     time.Now().UTC(),
		ContainerID:   cID,
		ContainerName: cName,
		PID:           9999,
		Syscall:       "execve",
		Comm:          "/bin/bash",
		Args:          []string{"-c", "cat /etc/shadow"},
		ReturnValue:   0,
	}

	alertObj := h.EBPFEngine.Security().Evaluate(testEvent)

	msg := "Test event simulated"
	if alertObj != nil {
		msg = "Test anomaly triggered: " + alertObj.Summary
	}

	if h.AuditLogger != nil {
		h.AuditLogger.Log(audit.AuditEvent{
			Action:  "ebpf_trigger_test",
			Target:  cID,
			Details: map[string]any{"alert_triggered": alertObj != nil},
		})
	}

	writeJSONResponse(w, http.StatusOK, EBPFActionResponse{
		Success:   true,
		Action:    "trigger_test",
		Message:   msg,
		Timestamp: time.Now().UTC(),
	})
}
