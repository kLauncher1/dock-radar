package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/healing"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// handleHealingConfig provides retrieval and updates for autonomous self-healing policy configuration.
func (h *HandlerConfig) handleHealingConfig(w http.ResponseWriter, r *http.Request) {
	if h.HealingEngine == nil {
		http.Error(w, "self-healing engine unavailable", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		writeJSONResponse(w, http.StatusOK, h.HealingEngine.PolicyStore().Get())

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}

		if !h.RateLimiter.Allow() {
			w.Header().Set("Retry-After", "2")
			http.Error(w, security.ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to read payload: %v", err), http.StatusBadRequest)
			return
		}

		var newCfg healing.PolicyConfig
		if err := json.Unmarshal(body, &newCfg); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
			return
		}

		if err := h.HealingEngine.PolicyStore().Update(newCfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Action:  "healing_policy_update",
				Target:  "dock-radar",
				Details: map[string]any{"enabled": newCfg.Enabled, "max_attempts": newCfg.MaxAttempts},
			})
		}

		writeJSONResponse(w, http.StatusOK, h.HealingEngine.PolicyStore().Get())

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleHealingStatus reports real-time self-healing metrics, active backoffs, and quarantined containers.
func (h *HandlerConfig) handleHealingStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.HealingEngine == nil {
		http.Error(w, "self-healing engine unavailable", http.StatusServiceUnavailable)
		return
	}

	stats := h.HealingEngine.Stats()
	writeJSONResponse(w, http.StatusOK, stats)
}

// handleHealingHistory serves structured remediation audit trail events.
func (h *HandlerConfig) handleHealingHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.HealingEngine == nil {
		http.Error(w, "self-healing engine unavailable", http.StatusServiceUnavailable)
		return
	}

	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	containerFilter := r.URL.Query().Get("container_id")
	triggerFilter := r.URL.Query().Get("trigger")

	events := h.HealingEngine.History().Recent(limit, containerFilter, triggerFilter)
	writeJSONResponse(w, http.StatusOK, events)
}

// handleHealingReset resets circuit breakers and active backoff timers for a specific container or all.
func (h *HandlerConfig) handleHealingReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if !h.RateLimiter.Allow() {
		w.Header().Set("Retry-After", "2")
		http.Error(w, security.ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
		return
	}

	if h.HealingEngine == nil {
		http.Error(w, "self-healing engine unavailable", http.StatusServiceUnavailable)
		return
	}

	// 1. Check Query parameter
	targetID := strings.TrimSpace(r.URL.Query().Get("id"))

	// 2. Fallback to JSON payload if query empty
	if targetID == "" && strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err == nil && len(body) > 0 {
			var payload struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(body, &payload); err == nil {
				targetID = strings.TrimSpace(payload.ID)
			}
		}
	}

	if targetID != "" {
		if err := docker.ValidateContainerID(targetID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		found := h.HealingEngine.ResetContainer(targetID)
		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Action:  "healing_reset_container",
				Target:  targetID,
				Details: map[string]any{"found": found},
			})
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success": true,
			"target":  targetID,
			"cleared": found,
			"message": fmt.Sprintf("Circuit breaker reset for container %s", targetID),
		})
	} else {
		h.HealingEngine.ResetAll()
		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Action: "healing_reset_all",
				Target: "dock-radar",
			})
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success": true,
			"message": "All self-healing circuit breakers and quarantined containers cleared",
		})
	}
}
