package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/security"
	"github.com/kLauncher1/dock-radar/internal/wireguard"
)

type wireguardHandshakeRequest struct {
	PeerID string `json:"peer_id"`
}

type wireguardKeygenResponse struct {
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
}

func (cfg *HandlerConfig) handleWireGuardStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.WireGuardEngine == nil {
		http.Error(w, "WireGuard engine not configured", http.StatusServiceUnavailable)
		return
	}

	status := cfg.WireGuardEngine.Status()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(status)
}

func (cfg *HandlerConfig) handleWireGuardPeers(w http.ResponseWriter, r *http.Request) {
	if cfg.WireGuardEngine == nil {
		http.Error(w, "WireGuard engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !cfg.authorize(w, r, security.RoleViewer) {
			return
		}
		peers := cfg.WireGuardEngine.ListPeers()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(peers)

	case http.MethodPost:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		var peer wireguard.PeerConfig
		if err := json.Unmarshal(body, &peer); err != nil {
			http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}

		added, err := cfg.WireGuardEngine.AddPeer(peer)
		if err != nil {
			http.Error(w, "Failed to add peer: "+err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(added)

	case http.MethodDelete:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		peerID := strings.TrimSpace(r.URL.Query().Get("id"))
		if peerID == "" {
			http.Error(w, "Missing required query parameter: id", http.StatusBadRequest)
			return
		}

		if !cfg.WireGuardEngine.RemovePeer(peerID) {
			http.Error(w, "Peer not found: "+peerID, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"action":  "remove_peer",
			"peer_id": peerID,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cfg *HandlerConfig) handleWireGuardHandshake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.WireGuardEngine == nil {
		http.Error(w, "WireGuard engine not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var req wireguardHandshakeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := cfg.WireGuardEngine.InitiateHandshake(req.PeerID); err != nil {
		http.Error(w, "Handshake failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"action":  "handshake",
		"peer_id": req.PeerID,
	})
}

func (cfg *HandlerConfig) handleWireGuardLeases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.WireGuardEngine == nil {
		http.Error(w, "WireGuard engine not configured", http.StatusServiceUnavailable)
		return
	}

	leases := cfg.WireGuardEngine.Pool().ListLeases()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(leases)
}

func (cfg *HandlerConfig) handleWireGuardReclaimLeases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.WireGuardEngine == nil {
		http.Error(w, "WireGuard engine not configured", http.StatusServiceUnavailable)
		return
	}

	count := cfg.WireGuardEngine.Pool().ReclaimExpired()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":   true,
		"reclaimed": count,
	})
}

func (cfg *HandlerConfig) handleWireGuardRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.WireGuardEngine == nil {
		http.Error(w, "WireGuard engine not configured", http.StatusServiceUnavailable)
		return
	}

	routes := cfg.WireGuardEngine.Router().ListRoutes()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(routes)
}

func (cfg *HandlerConfig) handleWireGuardKeygen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}

	kp, err := wireguard.GenerateKeyPair()
	if err != nil {
		http.Error(w, "Failed to generate keypair: "+err.Error(), http.StatusInternalServerError)
		return
	}

	psk, err := wireguard.GeneratePresharedKey()
	if err != nil {
		http.Error(w, "Failed to generate preshared key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := wireguardKeygenResponse{
		PrivateKey:   kp.PrivateKeyBase64,
		PublicKey:    kp.PublicKeyBase64,
		PresharedKey: psk,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

func (cfg *HandlerConfig) handleWireGuardConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.WireGuardEngine == nil {
		http.Error(w, "WireGuard engine not configured", http.StatusServiceUnavailable)
		return
	}

	config := cfg.WireGuardEngine.Config()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(config)
}
