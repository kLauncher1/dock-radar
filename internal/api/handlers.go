package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/logs"
	"github.com/kLauncher1/dock-radar/internal/mesh"
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

// HandlerConfig encapsulates services, buffers, and security policies.
type HandlerConfig struct {
	DockerClient     *docker.Client
	RateLimiter      *security.RateLimiter
	LogBuffer        *logs.RingBuffer
	AlertConfigStore *alert.ConfigStore
	AlertDispatcher  *alert.Dispatcher
	AlertMonitor     *alert.Monitor
	AuditLogger      *audit.Logger
	MeshRegistry     *mesh.Registry
	MeshProber       *mesh.Prober
	AppVersion       string
	TokenAuth        *security.TokenAuth
	AllowRemote      bool
}

// RegisterRoutes sets up all API endpoints and static file serving on the provided ServeMux.
func RegisterRoutes(mux *http.ServeMux, dockerClient *docker.Client, staticFS fs.FS) *HandlerConfig {
	return RegisterRoutesWithSecurity(mux, dockerClient, staticFS, nil, false)
}

// RegisterRoutesWithSecurity sets up API endpoints with Bearer token authentication and remote access policies.
func RegisterRoutesWithSecurity(mux *http.ServeMux, dockerClient *docker.Client, staticFS fs.FS, tokenAuth *security.TokenAuth, allowRemote bool) *HandlerConfig {
	// Initialize a burst of 5 actions with 1 refill per second
	limiter := security.NewRateLimiter(5.0, 1.0)
	ringBuffer := logs.NewRingBuffer(2000)
	ringBuffer.Append(logs.LogEntry{
		ID:        "system",
		Stream:    "system",
		Timestamp: time.Now().UTC(),
		Message:   "Dock-Radar single-binary engine initialized.",
	})

	alertCfgStore := alert.NewConfigStore(alert.DefaultConfig())
	alertDispatcher := alert.NewDispatcher(alertCfgStore)
	alertMonitor := alert.NewMonitor(dockerClient, alertCfgStore, alertDispatcher)
	auditLogger := audit.NewLogger(2000)
	auditLogger.Log(audit.AuditEvent{
		Action:  "system_init",
		Target:  "dock-radar",
		Details: map[string]any{"version": "1.3.0"},
	})

	cfg := &HandlerConfig{
		DockerClient:     dockerClient,
		RateLimiter:      limiter,
		LogBuffer:        ringBuffer,
		AlertConfigStore: alertCfgStore,
		AlertDispatcher:  alertDispatcher,
		AlertMonitor:     alertMonitor,
		AuditLogger:      auditLogger,
		AppVersion:       "1.3.0",
		TokenAuth:        tokenAuth,
		AllowRemote:      allowRemote,
	}

	// Real-time system telemetry
	mux.HandleFunc("/api/system", cfg.handleSystemMetrics)

	// Docker daemon & container inspection
	mux.HandleFunc("/api/docker", cfg.handleDockerStatus)

	// Container lifecycle controls
	mux.HandleFunc("/api/docker/restart", cfg.handleContainerRestart)
	mux.HandleFunc("/api/docker/stop", cfg.handleContainerStop)

	// Real-time log streaming & WebSocket feed
	mux.HandleFunc("/api/docker/logs", cfg.handleContainerLogs)

	// Interactive in-browser container shell execution via WebSocket
	mux.HandleFunc("/api/docker/exec", cfg.handleContainerExec)

	// Prometheus metrics exporter endpoint
	mux.HandleFunc("/metrics", cfg.handlePrometheusMetrics)

	// Batch container actions
	mux.HandleFunc("/api/docker/batch", cfg.handleBatchAction)

	// Audit trail export
	mux.HandleFunc("/api/audit/export", cfg.handleAuditExport)

	// Alert configurations & webhook channels
	mux.HandleFunc("/api/alerts/config", cfg.handleAlertConfig)
	mux.HandleFunc("/api/alerts/events", cfg.handleAlertEvents)
	mux.HandleFunc("/api/alerts/test", cfg.handleAlertTest)

	// Authentication status and token verification
	mux.HandleFunc("/api/auth/status", cfg.handleAuthStatus)
	mux.HandleFunc("/api/auth/verify", cfg.handleAuthVerify)

	// Multi-Host Agent Mesh & Remote Node Aggregator
	mux.HandleFunc("/api/nodes", cfg.handleMeshNodes)
	mux.HandleFunc("/api/nodes/register", cfg.handleMeshNodes)
	mux.HandleFunc("/api/nodes/heartbeat", cfg.handleNodeHeartbeat)
	mux.HandleFunc("/api/cluster/summary", cfg.handleClusterSummary)
	mux.HandleFunc("/api/cluster/containers", cfg.handleClusterContainers)

	// Embedded Static UI
	if staticFS != nil {
		mux.Handle("/", http.FileServer(http.FS(staticFS)))
	}

	return cfg
}

func (h *HandlerConfig) authorize(w http.ResponseWriter, r *http.Request, required security.Role) bool {
	if h.TokenAuth != nil && h.TokenAuth.IsEnabled() {
		_, err := h.TokenAuth.Authorize(r, required)
		if err != nil {
			if errors.Is(err, security.ErrUnauthorized) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="dock-radar"`)
				http.Error(w, err.Error(), http.StatusUnauthorized)
			} else {
				http.Error(w, err.Error(), http.StatusForbidden)
			}
			return false
		}
		return true
	}

	if required == security.RoleAdmin {
		if err := security.ValidateLoopbackOrigin(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return false
		}
	}
	return true
}

func (h *HandlerConfig) handleSystemMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
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
	if !h.authorize(w, r, security.RoleViewer) {
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

	if !h.authorize(w, r, security.RoleAdmin) {
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
	if timeout > 300 {
		timeout = 300
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

	if !h.authorize(w, r, security.RoleAdmin) {
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
	if timeout > 300 {
		timeout = 300
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

func (h *HandlerConfig) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	containerID := strings.TrimSpace(r.URL.Query().Get("id"))
	if containerID == "" {
		containerID = "system"
	} else if containerID != "system" {
		if err := docker.ValidateContainerID(containerID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	streamFilter := strings.TrimSpace(r.URL.Query().Get("stream"))
	tail := 100
	if tailStr := r.URL.Query().Get("tail"); tailStr != "" {
		if t, err := strconv.Atoi(tailStr); err == nil && t > 0 {
			tail = t
		}
	}

	// 1. WebSocket Upgrade Path
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		h.streamLogsWebSocket(w, r, containerID, streamFilter, tail)
		return
	}

	// 2. Standard REST JSON Snapshot Path
	w.Header().Set("Content-Type", "application/json")
	var entries []logs.LogEntry
	if containerID != "system" && h.DockerClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		dockerLogs, err := h.DockerClient.FetchLogs(ctx, containerID, tail)
		if err == nil {
			for _, dl := range dockerLogs {
				entry := logs.LogEntry{
					ID:        dl.ContainerID,
					Stream:    dl.Stream,
					Timestamp: dl.Timestamp,
					Message:   dl.Message,
				}
				entries = append(entries, entry)
				h.LogBuffer.Append(entry)
			}
		}
	}

	if len(entries) == 0 {
		entries = h.LogBuffer.Recent(tail, streamFilter)
	}
	_ = json.NewEncoder(w).Encode(entries)
}

func (h *HandlerConfig) streamLogsWebSocket(w http.ResponseWriter, r *http.Request, containerID, streamFilter string, tail int) {
	ws, err := UpgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("websocket upgrade failed: %v", err), http.StatusBadRequest)
		return
	}
	defer ws.Close()

	// Initial buffer dump
	initial := h.LogBuffer.Recent(tail, streamFilter)
	for _, entry := range initial {
		data, _ := json.Marshal(entry)
		if err := ws.WriteTextMessage(data); err != nil {
			return
		}
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		for {
			_, _, err := ws.ReadFrame()
			if err != nil {
				cancel()
				return
			}
		}
	}()

	if containerID != "system" && h.DockerClient != nil {
		logChan := make(chan docker.LogMessage, 50)
		go func() {
			_ = h.DockerClient.StreamLogs(ctx, containerID, tail, logChan)
			close(logChan)
		}()

		for {
			select {
			case <-clientDone:
				return
			case <-ctx.Done():
				return
			case msg, ok := <-logChan:
				if !ok {
					return
				}
				entry := logs.LogEntry{
					ID:        msg.ContainerID,
					Stream:    msg.Stream,
					Timestamp: msg.Timestamp,
					Message:   msg.Message,
				}
				h.LogBuffer.Append(entry)
				if streamFilter == "" || streamFilter == "all" || strings.EqualFold(entry.Stream, streamFilter) {
					data, _ := json.Marshal(entry)
					if err := ws.WriteTextMessage(data); err != nil {
						return
					}
				}
			}
		}
	} else {
		ticker := time.NewTicker(4 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-clientDone:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				entry := logs.LogEntry{
					ID:        "system",
					Stream:    "system",
					Timestamp: time.Now().UTC(),
					Message:   fmt.Sprintf("Dock-Radar telemetry heartbeat (Goroutines: %d)", runtime.NumGoroutine()),
				}
				h.LogBuffer.Append(entry)
				if streamFilter == "" || streamFilter == "all" || streamFilter == "system" {
					data, _ := json.Marshal(entry)
					if err := ws.WriteTextMessage(data); err != nil {
						return
					}
				}
			}
		}
	}
}

