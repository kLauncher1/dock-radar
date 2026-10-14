package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/mesh"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// NodeRegisterRequest parses the payload to register a new remote node in the mesh.
type NodeRegisterRequest struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Address string            `json:"address"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// NodeHeartbeatRequest parses the payload pushed by remote nodes for status and container synchronization.
type NodeHeartbeatRequest struct {
	NodeID     string                 `json:"node_id"`
	Status     mesh.NodeStatus        `json:"status"`
	LatencyMs  int64                  `json:"latency_ms"`
	Metrics    mesh.NodeMetrics       `json:"metrics"`
	Containers []mesh.RemoteContainer `json:"containers"`
}

func (h *HandlerConfig) handleMeshNodes(w http.ResponseWriter, r *http.Request) {
	if h.MeshRegistry == nil {
		http.Error(w, "mesh registry not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		nodes := h.MeshRegistry.List()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"nodes": nodes,
			"total": len(nodes),
		})

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		var req NodeRegisterRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid json payload", http.StatusBadRequest)
			return
		}
		req.ID = strings.TrimSpace(req.ID)
		if err := mesh.ValidateNodeID(req.ID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		node := &mesh.Node{
			ID:      req.ID,
			Name:    req.Name,
			Address: req.Address,
			Labels:  req.Labels,
			Status:  mesh.NodeStatusUnknown,
		}
		if err := h.MeshRegistry.Register(node); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if h.MeshProber != nil {
			go h.MeshProber.ProbeNode(context.Background(), node)
		}
		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Action:  "mesh_node_register",
				Target:  node.ID,
				Details: map[string]any{"address": node.Address, "name": node.Name},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"node":    node,
		})

	case http.MethodDelete:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		nodeID := strings.TrimSpace(r.URL.Query().Get("id"))
		if nodeID == "" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4*1024))
			var unregReq struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(body, &unregReq)
			nodeID = strings.TrimSpace(unregReq.ID)
		}
		if err := mesh.ValidateNodeID(nodeID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !h.MeshRegistry.Unregister(nodeID) {
			http.Error(w, "node not found", http.StatusNotFound)
			return
		}
		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Action: "mesh_node_unregister",
				Target: nodeID,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"id":      nodeID,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HandlerConfig) handleClusterSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.MeshRegistry == nil {
		http.Error(w, "mesh registry not configured", http.StatusServiceUnavailable)
		return
	}
	summary := h.MeshRegistry.ClusterSummary()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}

func (h *HandlerConfig) handleClusterContainers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.MeshRegistry == nil {
		http.Error(w, "mesh registry not configured", http.StatusServiceUnavailable)
		return
	}

	nodeFilter := strings.TrimSpace(r.URL.Query().Get("node_id"))
	stateFilter := strings.TrimSpace(r.URL.Query().Get("state"))

	all := h.MeshRegistry.AllContainers()
	filtered := make([]mesh.RemoteContainer, 0, len(all))
	for _, c := range all {
		if nodeFilter != "" && !strings.EqualFold(c.NodeID, nodeFilter) {
			continue
		}
		if stateFilter != "" && !strings.EqualFold(c.State, stateFilter) {
			continue
		}
		filtered = append(filtered, c)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"containers": filtered,
		"total":      len(filtered),
	})
}

func (h *HandlerConfig) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.MeshRegistry == nil {
		http.Error(w, "mesh registry not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 512*1024))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	var req NodeHeartbeatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}

	req.NodeID = strings.TrimSpace(req.NodeID)
	if err := mesh.ValidateNodeID(req.NodeID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.MeshRegistry.UpdateNodeStatus(req.NodeID, req.Status, req.LatencyMs, req.Metrics, req.Containers, "")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"node_id": req.NodeID,
	})
}
