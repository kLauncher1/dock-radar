package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/logs"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// handleContainerLogs handles log inspection over REST and live WebSocket streaming.
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

// streamLogsWebSocket maintains a persistent RFC 6455 connection for real-time log feeds.
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
