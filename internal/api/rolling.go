package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/rolling"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// RollingStartResponse encapsulates the result of kicking off a rolling restart.
type RollingStartResponse struct {
	Success   bool                      `json:"success"`
	Operation *rolling.RollingOperation `json:"operation,omitempty"`
	Message   string                    `json:"message,omitempty"`
	Error     string                    `json:"error,omitempty"`
}

// RollingStatusResponse summarizes rolling restart engine telemetry.
type RollingStatusResponse struct {
	Stats            rolling.RollingStats        `json:"stats"`
	ActiveOperations []*rolling.RollingOperation `json:"active_operations"`
	TotalRecorded    int                         `json:"total_recorded"`
}

// RollingOperationsResponse lists historical rolling restart executions.
type RollingOperationsResponse struct {
	Operations []*rolling.RollingOperation `json:"operations"`
	Count      int                         `json:"count"`
}

// RollingAbortRequest provides input for cancelling an active rolling restart.
type RollingAbortRequest struct {
	ID string `json:"id"`
}

// RollingAbortResponse describes the result of an abort attempt.
type RollingAbortResponse struct {
	Success bool   `json:"success"`
	ID      string `json:"id"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (h *HandlerConfig) handleRollingStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if h.RollingEngine == nil {
		writeJSONResponse(w, http.StatusServiceUnavailable, RollingStartResponse{
			Success: false,
			Error:   "rolling restart engine is not initialized",
		})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
	if err != nil {
		writeJSONResponse(w, http.StatusBadRequest, RollingStartResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to read request body: %v", err),
		})
		return
	}

	var cfg rolling.RollingPlanConfig
	if len(body) > 0 {
		if err := json.Unmarshal(body, &cfg); err != nil {
			writeJSONResponse(w, http.StatusBadRequest, RollingStartResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid JSON payload: %v", err),
			})
			return
		}
	} else {
		writeJSONResponse(w, http.StatusBadRequest, RollingStartResponse{
			Success: false,
			Error:   "request body cannot be empty",
		})
		return
	}

	op, err := h.RollingEngine.StartOperation(r.Context(), cfg)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, rolling.ErrNoContainersFound) {
			status = http.StatusNotFound
		}
		writeJSONResponse(w, status, RollingStartResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	writeJSONResponse(w, http.StatusAccepted, RollingStartResponse{
		Success:   true,
		Operation: op,
		Message:   fmt.Sprintf("Rolling restart operation %s initiated successfully", op.ID),
	})
}

func (h *HandlerConfig) handleRollingStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.RollingEngine == nil {
		writeJSONResponse(w, http.StatusOK, RollingStatusResponse{
			Stats:            rolling.RollingStats{},
			ActiveOperations: []*rolling.RollingOperation{},
			TotalRecorded:    0,
		})
		return
	}

	stats := h.RollingEngine.Stats()
	active := h.RollingEngine.Store().Active()
	total := h.RollingEngine.Store().Count()

	writeJSONResponse(w, http.StatusOK, RollingStatusResponse{
		Stats:            stats,
		ActiveOperations: active,
		TotalRecorded:    total,
	})
}

func (h *HandlerConfig) handleRollingOperations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.RollingEngine == nil {
		writeJSONResponse(w, http.StatusOK, RollingOperationsResponse{
			Operations: []*rolling.RollingOperation{},
			Count:      0,
		})
		return
	}

	// Priority 1: Direct ID query
	targetID := r.URL.Query().Get("id")
	if targetID != "" {
		op, found := h.RollingEngine.Store().Get(targetID)
		if !found {
			writeJSONResponse(w, http.StatusNotFound, map[string]string{
				"error": fmt.Sprintf("operation '%s' not found", targetID),
			})
			return
		}
		writeJSONResponse(w, http.StatusOK, op)
		return
	}

	// Priority 2: List with limit
	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}

	ops := h.RollingEngine.Store().List(limit)
	writeJSONResponse(w, http.StatusOK, RollingOperationsResponse{
		Operations: ops,
		Count:      len(ops),
	})
}

func (h *HandlerConfig) handleRollingAbort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if h.RollingEngine == nil {
		writeJSONResponse(w, http.StatusServiceUnavailable, RollingAbortResponse{
			Success: false,
			Error:   "rolling restart engine is not initialized",
		})
		return
	}

	var req RollingAbortRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err == nil && len(body) > 0 {
		_ = json.Unmarshal(body, &req)
	}

	if req.ID == "" {
		req.ID = r.URL.Query().Get("id")
	}

	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		writeJSONResponse(w, http.StatusBadRequest, RollingAbortResponse{
			Success: false,
			Error:   "operation id is required",
		})
		return
	}

	err = h.RollingEngine.AbortOperation(req.ID)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if errors.Is(err, rolling.ErrOperationNotActive) {
			statusCode = http.StatusConflict
		}
		writeJSONResponse(w, statusCode, RollingAbortResponse{
			Success: false,
			ID:      req.ID,
			Error:   err.Error(),
		})
		return
	}

	writeJSONResponse(w, http.StatusOK, RollingAbortResponse{
		Success: true,
		ID:      req.ID,
		Message: fmt.Sprintf("Operation %s successfully aborted", req.ID),
	})
}
