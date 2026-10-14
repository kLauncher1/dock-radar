package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// BatchRequest parses incoming parameters for multi-container batch operations.
type BatchRequest struct {
	Action  string `json:"action"`            // "restart_all", "stop_all", "prune"
	Timeout int    `json:"timeout,omitempty"` // Timeout seconds for container operations
}

// BatchResponse returns structured feedback for batch invocations.
type BatchResponse struct {
	Success   bool      `json:"success"`
	Action    string    `json:"action"`
	Message   string    `json:"message"`
	Data      any       `json:"data,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

func (h *HandlerConfig) handleBatchAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if h.RateLimiter != nil && !h.RateLimiter.Allow() {
		w.Header().Set("Retry-After", "2")
		http.Error(w, security.ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
		return
	}

	req, err := parseBatchRequest(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid batch request: %v", err), http.StatusBadRequest)
		return
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 10
	}
	if timeout > 300 {
		timeout = 300
	}

	clientIP := extractClientIP(r)
	actor := "admin"
	if h.TokenAuth != nil && h.TokenAuth.IsEnabled() {
		if role, err := h.TokenAuth.Authorize(r, security.RoleAdmin); err == nil {
			actor = string(role)
		}
	}

	ctx := r.Context()
	action := strings.ToLower(strings.TrimSpace(req.Action))

	switch action {
	case "restart_all":
		summary, err := h.DockerClient.RestartAll(ctx, timeout)
		status := "success"
		msg := fmt.Sprintf("Restarted %d/%d running containers", summary.Succeeded, summary.Total)
		if err != nil {
			status = "failed"
			msg = err.Error()
		}

		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Actor:    actor,
				ClientIP: clientIP,
				Action:   "batch_restart_all",
				Target:   "all_containers",
				Status:   status,
				Details: map[string]any{
					"total":     summary.Total,
					"succeeded": summary.Succeeded,
					"failed":    summary.Failed,
				},
			})
		}

		if err != nil {
			writeJSONResponse(w, http.StatusInternalServerError, BatchResponse{
				Success:   false,
				Action:    action,
				Message:   msg,
				Data:      summary,
				Timestamp: time.Now().UTC(),
			})
			return
		}

		writeJSONResponse(w, http.StatusOK, BatchResponse{
			Success:   true,
			Action:    action,
			Message:   msg,
			Data:      summary,
			Timestamp: time.Now().UTC(),
		})

	case "stop_all":
		summary, err := h.DockerClient.StopAll(ctx, timeout)
		status := "success"
		msg := fmt.Sprintf("Stopped %d/%d running containers", summary.Succeeded, summary.Total)
		if err != nil {
			status = "failed"
			msg = err.Error()
		}

		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Actor:    actor,
				ClientIP: clientIP,
				Action:   "batch_stop_all",
				Target:   "all_containers",
				Status:   status,
				Details: map[string]any{
					"total":     summary.Total,
					"succeeded": summary.Succeeded,
					"failed":    summary.Failed,
				},
			})
		}

		if err != nil {
			writeJSONResponse(w, http.StatusInternalServerError, BatchResponse{
				Success:   false,
				Action:    action,
				Message:   msg,
				Data:      summary,
				Timestamp: time.Now().UTC(),
			})
			return
		}

		writeJSONResponse(w, http.StatusOK, BatchResponse{
			Success:   true,
			Action:    action,
			Message:   msg,
			Data:      summary,
			Timestamp: time.Now().UTC(),
		})

	case "prune":
		report, err := h.DockerClient.PruneContainers(ctx)
		status := "success"
		msg := fmt.Sprintf("Pruned %d inactive containers, reclaimed %d bytes", len(report.ContainersDeleted), report.SpaceReclaimed)
		if err != nil {
			status = "failed"
			msg = err.Error()
		}

		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Actor:    actor,
				ClientIP: clientIP,
				Action:   "batch_prune",
				Target:   "inactive_containers",
				Status:   status,
				Details: map[string]any{
					"deleted_count":   len(report.ContainersDeleted),
					"space_reclaimed": report.SpaceReclaimed,
				},
			})
		}

		if err != nil {
			writeJSONResponse(w, http.StatusInternalServerError, BatchResponse{
				Success:   false,
				Action:    action,
				Message:   msg,
				Data:      report,
				Timestamp: time.Now().UTC(),
			})
			return
		}

		writeJSONResponse(w, http.StatusOK, BatchResponse{
			Success:   true,
			Action:    action,
			Message:   msg,
			Data:      report,
			Timestamp: time.Now().UTC(),
		})

	default:
		http.Error(w, fmt.Sprintf("unsupported batch action '%s': must be restart_all, stop_all, or prune", action), http.StatusBadRequest)
	}
}

func parseBatchRequest(r *http.Request) (BatchRequest, error) {
	var req BatchRequest
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err == nil && len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				return req, err
			}
		}
	}
	if req.Action == "" {
		req.Action = r.URL.Query().Get("action")
	}
	if req.Action == "" {
		return req, fmt.Errorf("action is required (restart_all, stop_all, prune)")
	}
	return req, nil
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
