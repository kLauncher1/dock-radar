package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/security"
	"github.com/kLauncher1/dock-radar/internal/system"
)

// ActionRequest parses input parameters for container control endpoints.
type ActionRequest struct {
	ID      string `json:"id"`
	Timeout int    `json:"timeout,omitempty"`
}

// ActionResponse provides structured results for container control invocations.
type ActionResponse struct {
	Success   bool      `json:"success"`
	Action    string    `json:"action"`
	ID        string    `json:"id"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// HandlerConfig encapsulates services and security policies.
type HandlerConfig struct {
	DockerClient *docker.Client
	RateLimiter  *security.RateLimiter
}

// RegisterRoutes sets up all API endpoints and static file serving on the provided ServeMux.
func RegisterRoutes(mux *http.ServeMux, dockerClient *docker.Client, staticFS fs.FS) {
	// Initialize a burst of 5 actions with 1 refill per second
	limiter := security.NewRateLimiter(5.0, 1.0)
	cfg := &HandlerConfig{
		DockerClient: dockerClient,
		RateLimiter:  limiter,
	}

	// Real-time system telemetry
	mux.HandleFunc("/api/system", cfg.handleSystemMetrics)

	// Docker daemon & container inspection
	mux.HandleFunc("/api/docker", cfg.handleDockerStatus)

	// Container lifecycle controls
	mux.HandleFunc("/api/docker/restart", cfg.handleContainerRestart)
	mux.HandleFunc("/api/docker/stop", cfg.handleContainerStop)

	// Embedded Static UI
	if staticFS != nil {
		mux.Handle("/", http.FileServer(http.FS(staticFS)))
	}
}

func (h *HandlerConfig) handleSystemMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	metrics := system.CollectTelemetry()
	_ = json.NewEncoder(w).Encode(metrics)
}

func (h *HandlerConfig) handleDockerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	status := h.DockerClient.InspectContainers()
	_ = json.NewEncoder(w).Encode(status)
}

func (h *HandlerConfig) handleContainerRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := security.ValidateLoopbackOrigin(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if !h.RateLimiter.Allow() {
		w.Header().Set("Retry-After", "2")
		http.Error(w, security.ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
		return
	}

	req, err := parseActionRequest(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid request payload: %v", err), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 10
	}

	err = h.DockerClient.RestartContainer(ctx, req.ID, timeout)
	if err != nil {
		handleLifecycleError(w, "restart", req.ID, err)
		return
	}

	writeJSONResponse(w, http.StatusOK, ActionResponse{
		Success:   true,
		Action:    "restart",
		ID:        req.ID,
		Message:   fmt.Sprintf("container %s successfully restarted", req.ID),
		Timestamp: time.Now().UTC(),
	})
}

func (h *HandlerConfig) handleContainerStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := security.ValidateLoopbackOrigin(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if !h.RateLimiter.Allow() {
		w.Header().Set("Retry-After", "2")
		http.Error(w, security.ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
		return
	}

	req, err := parseActionRequest(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid request payload: %v", err), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 10
	}

	err = h.DockerClient.StopContainer(ctx, req.ID, timeout)
	if err != nil {
		handleLifecycleError(w, "stop", req.ID, err)
		return
	}

	writeJSONResponse(w, http.StatusOK, ActionResponse{
		Success:   true,
		Action:    "stop",
		ID:        req.ID,
		Message:   fmt.Sprintf("container %s successfully stopped", req.ID),
		Timestamp: time.Now().UTC(),
	})
}

func parseActionRequest(r *http.Request) (ActionRequest, error) {
	var req ActionRequest

	// Priority 1: JSON body
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err == nil && len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				return req, err
			}
		}
	}

	// Priority 2: Query param fallback
	if req.ID == "" {
		req.ID = r.URL.Query().Get("id")
	}

	if err := docker.ValidateContainerID(req.ID); err != nil {
		return req, err
	}

	return req, nil
}

func handleLifecycleError(w http.ResponseWriter, action, id string, err error) {
	statusCode := http.StatusInternalServerError
	if errors.Is(err, docker.ErrContainerNotFound) {
		statusCode = http.StatusNotFound
	} else if errors.Is(err, docker.ErrInvalidContainerID) {
		statusCode = http.StatusBadRequest
	} else if errors.Is(err, docker.ErrDaemonUnreachable) {
		statusCode = http.StatusBadGateway
	}

	writeJSONResponse(w, statusCode, ActionResponse{
		Success:   false,
		Action:    action,
		ID:        id,
		Message:   err.Error(),
		Timestamp: time.Now().UTC(),
	})
}

func writeJSONResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
