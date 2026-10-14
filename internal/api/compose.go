package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// ComposeStacksResponse represents the response envelope for listing compose stacks.
type ComposeStacksResponse struct {
	Stacks    []docker.ComposeStack `json:"stacks"`
	Count     int                   `json:"count"`
	CheckedAt time.Time             `json:"checked_at"`
}

// ComposeActionRequest specifies parameters for whole-stack control actions.
type ComposeActionRequest struct {
	Project string `json:"project"`
	Action  string `json:"action"` // "restart", "stop", "recreate"
}

// ComposeActionResponse provides structured execution outcomes of stack actions.
type ComposeActionResponse struct {
	Success bool                     `json:"success"`
	Action  string                   `json:"action"`
	Project string                   `json:"project"`
	Result  docker.StackActionResult `json:"result"`
	Error   string                   `json:"error,omitempty"`
}

// handleComposeStacks inspects active containers and returns grouped compose stacks and topologies.
func (h *HandlerConfig) handleComposeStacks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if !h.RateLimiter.Allow() {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	daemonStatus := h.DockerClient.InspectContainers()
	stacks := docker.ExtractComposeStacks(daemonStatus.Containers)

	projFilter := strings.TrimSpace(r.URL.Query().Get("project"))
	if projFilter != "" {
		var filtered []docker.ComposeStack
		for _, s := range stacks {
			if strings.EqualFold(s.Project, projFilter) {
				filtered = append(filtered, s)
			}
		}
		stacks = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ComposeStacksResponse{
		Stacks:    stacks,
		Count:     len(stacks),
		CheckedAt: time.Now().UTC(),
	})
}

// handleComposeAction executes synchronized restart, stop, or recreation across a compose stack.
func (h *HandlerConfig) handleComposeAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if !h.RateLimiter.Allow() {
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	var req ComposeActionRequest
	bodyReader := io.LimitReader(r.Body, 4096)
	if err := json.NewDecoder(bodyReader).Decode(&req); err != nil {
		http.Error(w, "Bad Request: invalid JSON body", http.StatusBadRequest)
		return
	}

	req.Project = strings.TrimSpace(req.Project)
	if err := docker.ValidateProjectName(req.Project); err != nil {
		http.Error(w, fmt.Sprintf("Bad Request: %v", err), http.StatusBadRequest)
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action != "restart" && action != "stop" && action != "recreate" {
		http.Error(w, "Bad Request: action must be 'restart', 'stop', or 'recreate'", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	var result docker.StackActionResult
	var actionErr error

	switch action {
	case "restart":
		result, actionErr = h.DockerClient.RestartStack(ctx, req.Project)
	case "stop":
		result, actionErr = h.DockerClient.StopStack(ctx, req.Project)
	case "recreate":
		result, actionErr = h.DockerClient.RecreateStack(ctx, req.Project)
	}

	clientIP := r.RemoteAddr
	statusStr := "success"
	if actionErr != nil {
		statusStr = "failure"
	} else if result.FailureCount > 0 {
		statusStr = "partial_failure"
	}

	if h.AuditLogger != nil {
		h.AuditLogger.Log(audit.AuditEvent{
			Action:   fmt.Sprintf("compose_stack_%s", action),
			Target:   req.Project,
			Actor:    "admin",
			ClientIP: clientIP,
			Status:   statusStr,
			Details: map[string]any{
				"affected_containers": result.AffectedContainers,
				"success_count":       result.SuccessCount,
				"failure_count":       result.FailureCount,
				"errors":              result.Errors,
			},
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if actionErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ComposeActionResponse{
			Success: false,
			Action:  action,
			Project: req.Project,
			Result:  result,
			Error:   actionErr.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(ComposeActionResponse{
		Success: result.FailureCount == 0,
		Action:  action,
		Project: req.Project,
		Result:  result,
	})
}
