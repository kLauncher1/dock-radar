package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// ExecClientMessage represents client-to-server WebSocket messages.
type ExecClientMessage struct {
	Type string `json:"type"` // "stdin", "resize", "ping"
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// ExecServerMessage represents server-to-client WebSocket messages.
type ExecServerMessage struct {
	Type     string `json:"type"` // "output", "status", "warning", "error", "exit", "timeout", "pong"
	Data     string `json:"data,omitempty"`
	Message  string `json:"message,omitempty"`
	ExecID   string `json:"exec_id,omitempty"`
	ID       string `json:"id,omitempty"`
	Code     int    `json:"code,omitempty"`
	ReadOnly bool   `json:"readonly,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
}

// handleContainerExec manages both interactive WebSocket shell execution and REST exec creation.
func (h *HandlerConfig) handleContainerExec(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// WebSocket interactive shell upgrade path
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			h.serveExecWebSocket(w, r)
			return
		}
		// REST query parameters check
		h.handleExecInfo(w, r)
	case http.MethodPost:
		h.handleExecCreateREST(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleExecInfo provides lightweight endpoint metadata for container exec capabilities.
func (h *HandlerConfig) handleExecInfo(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	containerID := strings.TrimSpace(r.URL.Query().Get("id"))
	if containerID != "" {
		if err := docker.ValidateContainerID(containerID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"endpoint":         "/api/docker/exec",
		"protocol":         "websocket-rfc6455",
		"default_shell":    "/bin/sh",
		"read_only_mode":   true,
		"max_idle_seconds": 3600,
	})
}

// handleExecCreateREST handles programmatic exec instance creation via standard REST POST.
func (h *HandlerConfig) handleExecCreateREST(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}
	if !h.RateLimiter.Allow() {
		w.Header().Set("Retry-After", "2")
		http.Error(w, security.ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
		return
	}

	var req struct {
		ID       string   `json:"id"`
		Cmd      []string `json:"cmd,omitempty"`
		ReadOnly bool     `json:"readonly,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request payload: %v", err), http.StatusBadRequest)
		return
	}

	if err := docker.ValidateContainerID(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg := docker.DefaultExecConfig()
	if len(req.Cmd) > 0 {
		cfg.Cmd = req.Cmd
	}
	cfg.ReadOnly = req.ReadOnly

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	execID, err := h.DockerClient.CreateExec(ctx, req.ID, cfg)
	if err != nil {
		if errors.Is(err, docker.ErrContainerNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	writeJSONResponse(w, http.StatusCreated, map[string]any{
		"success":  true,
		"exec_id":  execID,
		"id":       req.ID,
		"readonly": req.ReadOnly,
	})
}

// serveExecWebSocket upgrades HTTP to RFC 6455 WebSocket and tunnels container TTY duplex stream.
func (h *HandlerConfig) serveExecWebSocket(w http.ResponseWriter, r *http.Request) {
	// 1. Role-Based Access Control and Read-Only Policy Enforcement
	isReadOnly := false
	if h.TokenAuth != nil && h.TokenAuth.IsEnabled() {
		role, err := h.TokenAuth.Authorize(r, security.RoleViewer)
		if err != nil {
			if errors.Is(err, security.ErrUnauthorized) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="dock-radar"`)
				http.Error(w, err.Error(), http.StatusUnauthorized)
			} else {
				http.Error(w, err.Error(), http.StatusForbidden)
			}
			return
		}
		// Viewers are strictly confined to read-only policy mode
		if role == security.RoleViewer {
			isReadOnly = true
		}
	} else if !h.AllowRemote {
		if err := security.ValidateLoopbackOrigin(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
	}

	// Read explicit query flag
	roQuery := strings.TrimSpace(r.URL.Query().Get("readonly"))
	if roQuery == "true" || roQuery == "1" {
		isReadOnly = true
	}

	containerID := strings.TrimSpace(r.URL.Query().Get("id"))
	if containerID == "" {
		http.Error(w, "missing required container 'id' parameter", http.StatusBadRequest)
		return
	}
	if err := docker.ValidateContainerID(containerID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cmdStr := strings.TrimSpace(r.URL.Query().Get("cmd"))
	if cmdStr == "" {
		cmdStr = "/bin/sh"
	}
	// Sanitize command string to prevent argument injection
	if strings.ContainsAny(cmdStr, ";|&$`") {
		http.Error(w, "command contains disallowed shell meta-characters", http.StatusBadRequest)
		return
	}

	idleTimeout := 300 * time.Second
	if tStr := r.URL.Query().Get("timeout"); tStr != "" {
		if tSec, err := strconv.Atoi(tStr); err == nil && tSec >= 10 && tSec <= 3600 {
			idleTimeout = time.Duration(tSec) * time.Second
		}
	}

	// 2. Perform WebSocket Upgrade
	ws, err := UpgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("websocket upgrade failed: %v", err), http.StatusBadRequest)
		return
	}
	defer ws.Close()

	sendServerMsg := func(msg ExecServerMessage) error {
		payload, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		return ws.WriteTextMessage(payload)
	}

	_ = sendServerMsg(ExecServerMessage{
		Type:     "status",
		Message:  fmt.Sprintf("Attaching interactive exec session for container '%s'...", containerID),
		ID:       containerID,
		ReadOnly: isReadOnly,
		Timeout:  int(idleTimeout.Seconds()),
	})

	// 3. Create Docker Exec Instance
	execCfg := docker.DefaultExecConfig()
	execCfg.Cmd = []string{cmdStr}
	execCfg.ReadOnly = isReadOnly

	initCtx, initCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer initCancel()

	execID, err := h.DockerClient.CreateExec(initCtx, containerID, execCfg)
	if err != nil {
		_ = sendServerMsg(ExecServerMessage{
			Type:    "error",
			Message: fmt.Sprintf("failed to create exec instance: %v", err),
			ID:      containerID,
		})
		return
	}

	// 4. Start Docker Exec and Hijack Connection Stream
	connCtx, connCancel := context.WithCancel(context.Background())
	defer connCancel()

	dockerConn, dockerReader, err := h.DockerClient.StartExecHijack(connCtx, execID)
	if err != nil {
		_ = sendServerMsg(ExecServerMessage{
			Type:    "error",
			Message: fmt.Sprintf("failed to establish exec stream: %v", err),
			ID:      containerID,
			ExecID:  execID,
		})
		return
	}
	defer dockerConn.Close()

	if h.AuditLogger != nil {
		h.AuditLogger.Log(audit.AuditEvent{
			Action: "container_exec_start",
			Target: containerID,
			Details: map[string]any{
				"exec_id":      execID,
				"cmd":          cmdStr,
				"read_only":    isReadOnly,
				"idle_timeout": int(idleTimeout.Seconds()),
			},
		})
	}

	_ = sendServerMsg(ExecServerMessage{
		Type:     "status",
		Message:  fmt.Sprintf("Shell attached (%s). Session ready.", cmdStr),
		ID:       containerID,
		ExecID:   execID,
		ReadOnly: isReadOnly,
	})

	var lastActivity int64
	atomic.StoreInt64(&lastActivity, time.Now().Unix())

	stopSession := make(chan struct{})
	var closeOnce sync.Once
	shutdown := func(reason string) {
		closeOnce.Do(func() {
			close(stopSession)
			connCancel()
			_ = dockerConn.Close()
		})
	}

	// 5. Idle Timeout Watchdog
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopSession:
				return
			case <-ticker.C:
				last := atomic.LoadInt64(&lastActivity)
				if time.Since(time.Unix(last, 0)) > idleTimeout {
					_ = sendServerMsg(ExecServerMessage{
						Type:    "timeout",
						Message: fmt.Sprintf("Session terminated due to %d seconds of inactivity.", int(idleTimeout.Seconds())),
					})
					shutdown("idle timeout")
					return
				}
			}
		}
	}()

	// 6. Goroutine: Forward Docker container stdout/stderr -> WebSocket
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := dockerReader.Read(buf)
			if n > 0 {
				atomic.StoreInt64(&lastActivity, time.Now().Unix())
				if sendErr := sendServerMsg(ExecServerMessage{
					Type: "output",
					Data: string(buf[:n]),
				}); sendErr != nil {
					shutdown("client websocket closed")
					return
				}
			}
			if err != nil {
				// Query final exit code if available
				exitCode := 0
				inspectCtx, inspectCancel := context.WithTimeout(context.Background(), 2*time.Second)
				if inspect, inspectErr := h.DockerClient.InspectExec(inspectCtx, execID); inspectErr == nil && inspect != nil {
					exitCode = inspect.ExitCode
				}
				inspectCancel()

				_ = sendServerMsg(ExecServerMessage{
					Type:    "exit",
					Code:    exitCode,
					Message: "Container process exited",
				})
				shutdown("docker process terminated")
				return
			}
		}
	}()

	// 7. Goroutine: Receive client WebSocket messages -> Forward to Docker stdin / resize
	for {
		opcode, payload, err := ws.ReadFrame()
		if err != nil {
			shutdown("client disconnected")
			break
		}

		atomic.StoreInt64(&lastActivity, time.Now().Unix())

		if opcode != opText || len(payload) == 0 {
			continue
		}

		var clientMsg ExecClientMessage
		if err := json.Unmarshal(payload, &clientMsg); err != nil {
			// If not valid JSON, treat raw text as stdin
			clientMsg = ExecClientMessage{
				Type: "stdin",
				Data: string(payload),
			}
		}

		switch clientMsg.Type {
		case "stdin":
			if isReadOnly {
				_ = sendServerMsg(ExecServerMessage{
					Type:    "warning",
					Message: "Keystrokes blocked: session is operating in Read-Only Policy Mode",
				})
				continue
			}
			if len(clientMsg.Data) > 0 {
				if _, writeErr := io.WriteString(dockerConn, clientMsg.Data); writeErr != nil {
					shutdown("docker conn write error")
					break
				}
			}
		case "resize":
			if clientMsg.Cols > 0 && clientMsg.Rows > 0 {
				resizeCtx, resizeCancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = h.DockerClient.ResizeExec(resizeCtx, execID, clientMsg.Cols, clientMsg.Rows)
				resizeCancel()
			}
		case "ping":
			_ = sendServerMsg(ExecServerMessage{Type: "pong"})
		}
	}

	if h.AuditLogger != nil {
		h.AuditLogger.Log(audit.AuditEvent{
			Action: "container_exec_close",
			Target: containerID,
			Details: map[string]any{
				"exec_id": execID,
			},
		})
	}
}
