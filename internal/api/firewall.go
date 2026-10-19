package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/firewall"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// FirewallStatusResponse conveys firewall engine health and telemetry counters.
type FirewallStatusResponse struct {
	Status      firewall.FirewallStatus `json:"status"`
	GeneratedAt time.Time               `json:"generated_at"`
}

// FirewallRulesResponse lists active packet filtering rules.
type FirewallRulesResponse struct {
	Rules       []firewall.FirewallRule `json:"rules"`
	TotalCount  int                     `json:"total_count"`
	GeneratedAt time.Time               `json:"generated_at"`
}

// FirewallIsolationResponse lists container isolation postures and zero-trust policies.
type FirewallIsolationResponse struct {
	Isolations  []firewall.ContainerIsolationState `json:"isolations"`
	TotalCount  int                                `json:"total_count"`
	GeneratedAt time.Time                          `json:"generated_at"`
}

// FirewallBandwidthResponse conveys live container network throughput and metrics.
type FirewallBandwidthResponse struct {
	Stats       []firewall.BandwidthStats `json:"stats"`
	TotalCount  int                       `json:"total_count"`
	GeneratedAt time.Time                 `json:"generated_at"`
}

// FirewallDDoSAlertsResponse lists recent volumetric and bandwidth attack detections.
type FirewallDDoSAlertsResponse struct {
	Alerts      []firewall.DDoSAlertEvent `json:"alerts"`
	TotalCount  int                       `json:"total_count"`
	GeneratedAt time.Time                 `json:"generated_at"`
}

// IsolateContainerRequest parses payload for isolating or quarantining a container.
type IsolateContainerRequest struct {
	ContainerID     string                  `json:"container_id"`
	ContainerName   string                  `json:"container_name,omitempty"`
	IsolationLevel  firewall.IsolationLevel `json:"isolation_level"`
	Reason          string                  `json:"reason,omitempty"`
	AllowedPeers    []string                `json:"allowed_peers,omitempty"`
	EgressLimitBPS  uint64                  `json:"egress_limit_bps,omitempty"`
	IngressLimitBPS uint64                  `json:"ingress_limit_bps,omitempty"`
}

// UnisolateContainerRequest parses target container to restore normal networking.
type UnisolateContainerRequest struct {
	ContainerID string `json:"container_id"`
}

// handleFirewallStatus exposes live firewall operational state and packet statistics.
func (h *HandlerConfig) handleFirewallStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if h.FirewallEngine == nil {
		_ = json.NewEncoder(w).Encode(FirewallStatusResponse{
			Status:      firewall.FirewallStatus{Enabled: false},
			GeneratedAt: time.Now().UTC(),
		})
		return
	}

	st := h.FirewallEngine.Status()
	_ = json.NewEncoder(w).Encode(FirewallStatusResponse{
		Status:      st,
		GeneratedAt: time.Now().UTC(),
	})
}

// handleFirewallRules handles listing, creating, updating, and deleting packet filtering rules.
func (h *HandlerConfig) handleFirewallRules(w http.ResponseWriter, r *http.Request) {
	if h.FirewallEngine == nil {
		http.Error(w, "Firewall engine is unavailable", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		rules := h.FirewallEngine.ListRules()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(FirewallRulesResponse{
			Rules:       rules,
			TotalCount:  len(rules),
			GeneratedAt: time.Now().UTC(),
		})

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		var rule firewall.FirewallRule
		if err := json.Unmarshal(body, &rule); err != nil {
			http.Error(w, fmt.Sprintf("Malformed rule JSON: %v", err), http.StatusBadRequest)
			return
		}

		// Try updating if already exists, else add
		if _, exists := h.FirewallEngine.GetRule(rule.ID); exists {
			if err := h.FirewallEngine.UpdateRule(rule); err != nil {
				http.Error(w, fmt.Sprintf("Failed to update rule: %v", err), http.StatusBadRequest)
				return
			}
		} else {
			if err := h.FirewallEngine.AddRule(rule); err != nil {
				http.Error(w, fmt.Sprintf("Failed to add rule: %v", err), http.StatusBadRequest)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"rule_id": rule.ID,
			"message": "Firewall rule saved successfully",
		})

	case http.MethodDelete:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		ruleID := strings.TrimSpace(r.URL.Query().Get("id"))
		if ruleID == "" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			var payload struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(body, &payload)
			ruleID = strings.TrimSpace(payload.ID)
		}
		if ruleID == "" {
			http.Error(w, "Rule ID is required (?id=... or JSON {id: ...})", http.StatusBadRequest)
			return
		}

		if err := h.FirewallEngine.DeleteRule(ruleID); err != nil {
			http.Error(w, fmt.Sprintf("Failed to delete rule: %v", err), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"rule_id": ruleID,
			"message": "Firewall rule deleted successfully",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFirewallIsolation lists active container containment policies.
func (h *HandlerConfig) handleFirewallIsolation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.FirewallEngine == nil {
		http.Error(w, "Firewall engine is unavailable", http.StatusServiceUnavailable)
		return
	}

	isolations := h.FirewallEngine.ListIsolations()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(FirewallIsolationResponse{
		Isolations:  isolations,
		TotalCount:  len(isolations),
		GeneratedAt: time.Now().UTC(),
	})
}

// handleFirewallIsolate applies zero-trust isolation or full quarantine to a container.
func (h *HandlerConfig) handleFirewallIsolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}
	if h.FirewallEngine == nil {
		http.Error(w, "Firewall engine is unavailable", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	var req IsolateContainerRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("Malformed JSON: %v", err), http.StatusBadRequest)
		return
	}
	req.ContainerID = strings.TrimSpace(req.ContainerID)
	if req.ContainerID == "" {
		http.Error(w, "container_id is required", http.StatusBadRequest)
		return
	}
	if req.IsolationLevel == "" {
		req.IsolationLevel = firewall.IsolationStrictZero
	}

	st := h.FirewallEngine.IsolateContainer(
		req.ContainerID,
		req.ContainerName,
		req.IsolationLevel,
		req.Reason,
		req.AllowedPeers,
		req.EgressLimitBPS,
		req.IngressLimitBPS,
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":   true,
		"isolation": st,
		"message":   fmt.Sprintf("Container %s containment updated to %s", req.ContainerID, req.IsolationLevel),
	})
}

// handleFirewallUnisolate restores a container to normal networking.
func (h *HandlerConfig) handleFirewallUnisolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}
	if h.FirewallEngine == nil {
		http.Error(w, "Firewall engine is unavailable", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	var req UnisolateContainerRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("Malformed JSON: %v", err), http.StatusBadRequest)
		return
	}
	req.ContainerID = strings.TrimSpace(req.ContainerID)
	if req.ContainerID == "" {
		http.Error(w, "container_id is required", http.StatusBadRequest)
		return
	}

	removed := h.FirewallEngine.UnisolateContainer(req.ContainerID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":      removed,
		"container_id": req.ContainerID,
		"message":      fmt.Sprintf("Container %s restored to normal networking", req.ContainerID),
	})
}

// handleFirewallBandwidth provides real-time container network bandwidth consumption.
func (h *HandlerConfig) handleFirewallBandwidth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.FirewallEngine == nil {
		http.Error(w, "Firewall engine is unavailable", http.StatusServiceUnavailable)
		return
	}

	stats := h.FirewallEngine.BandwidthStats()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(FirewallBandwidthResponse{
		Stats:       stats,
		TotalCount:  len(stats),
		GeneratedAt: time.Now().UTC(),
	})
}

// handleFirewallDDoSAlerts lists recent DDoS alerts and mitigation triggers.
func (h *HandlerConfig) handleFirewallDDoSAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.FirewallEngine == nil {
		http.Error(w, "Firewall engine is unavailable", http.StatusServiceUnavailable)
		return
	}

	alerts := h.FirewallEngine.RecentDDoSAlerts(100)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(FirewallDDoSAlertsResponse{
		Alerts:      alerts,
		TotalCount:  len(alerts),
		GeneratedAt: time.Now().UTC(),
	})
}

// handleFirewallSimulate tests packet evaluation against active rules without changing network state.
func (h *HandlerConfig) handleFirewallSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.FirewallEngine == nil {
		http.Error(w, "Firewall engine is unavailable", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 32*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	var packet firewall.PacketPayload
	if err := json.Unmarshal(body, &packet); err != nil {
		http.Error(w, fmt.Sprintf("Malformed packet payload JSON: %v", err), http.StatusBadRequest)
		return
	}

	result := h.FirewallEngine.EvaluatePacket(packet)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// handleFirewallConfig inspects or mutates firewall runtime configuration.
func (h *HandlerConfig) handleFirewallConfig(w http.ResponseWriter, r *http.Request) {
	if h.FirewallEngine == nil {
		http.Error(w, "Firewall engine is unavailable", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h.FirewallEngine.Config())

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024))
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		var cfg firewall.FirewallConfig
		if err := json.Unmarshal(body, &cfg); err != nil {
			http.Error(w, fmt.Sprintf("Malformed config JSON: %v", err), http.StatusBadRequest)
			return
		}
		if err := h.FirewallEngine.UpdateConfig(cfg); err != nil {
			http.Error(w, fmt.Sprintf("Invalid configuration: %v", err), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"config":  h.FirewallEngine.Config(),
			"message": "Firewall configuration updated successfully",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
