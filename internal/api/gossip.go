package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/mesh"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// handleMeshDiscovery handles GET and POST requests for LAN auto-discovery status and manual beacon dispatch.
func (h *HandlerConfig) handleMeshDiscovery(w http.ResponseWriter, r *http.Request) {
	if h.MeshDiscovery == nil {
		http.Error(w, "LAN peer discovery engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		status := h.MeshDiscovery.Status()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		if h.RateLimiter != nil && !h.RateLimiter.Allow() {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		err := h.MeshDiscovery.BroadcastBeacon()
		if err != nil {
			http.Error(w, "failed to broadcast beacon: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Action: "discovery_beacon_broadcast",
				Target: "lan_broadcast",
				Status: "success",
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"message": "LAN discovery beacon broadcast dispatched",
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleMeshGossip handles GET requests for SWIM membership inspection and POST requests for peer-to-peer gossip ingestion.
func (h *HandlerConfig) handleMeshGossip(w http.ResponseWriter, r *http.Request) {
	if h.MeshGossip == nil {
		http.Error(w, "SWIM gossip consensus engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		summary := h.MeshGossip.Summary()
		members := h.MeshGossip.Members()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"summary": summary,
			"members": members,
		})

	case http.MethodPost:
		// Authenticate peer request if TokenAuth is enabled
		if h.TokenAuth != nil && h.TokenAuth.IsEnabled() {
			if !h.authorize(w, r, security.RoleViewer) {
				return
			}
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, mesh.MaxGossipPayloadBytes))
		if err != nil {
			http.Error(w, "failed to read gossip payload", http.StatusBadRequest)
			return
		}

		var msg mesh.GossipMessage
		if err := json.Unmarshal(body, &msg); err != nil {
			http.Error(w, "malformed gossip payload: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Process SWIM message and obtain optional piggybacked ACK response
		ack := h.MeshGossip.ProcessIncomingMessage(msg)

		w.Header().Set("Content-Type", "application/json")
		if ack != nil {
			_ = json.NewEncoder(w).Encode(ack)
		} else {
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
