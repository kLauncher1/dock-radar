package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/security"
	"github.com/kLauncher1/dock-radar/internal/vault"
)

type storeSecretRequest struct {
	Key        string            `json:"key"`
	Type       vault.SecretType  `json:"type"`
	Value      string            `json:"value"`
	TTLSeconds int               `json:"ttl_seconds,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type readSecretResponse struct {
	Key       string             `json:"key"`
	Value     string             `json:"value"`
	Lease     *vault.SecretLease `json:"lease,omitempty"`
	Timestamp time.Time          `json:"timestamp"`
}

type renewLeaseRequest struct {
	LeaseID       string `json:"lease_id"`
	ExtendSeconds int    `json:"extend_seconds"`
}

type revokeLeaseRequest struct {
	LeaseID string `json:"lease_id"`
}

type createJoinTokenRequest struct {
	Role       string `json:"role"`
	TTLSeconds int    `json:"ttl_seconds"`
	MaxUses    int    `json:"max_uses"`
}

type createJoinTokenResponse struct {
	Token     string    `json:"token"`
	TokenID   string    `json:"token_id"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
}

func (cfg *HandlerConfig) handleVaultStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.VaultEngine == nil {
		http.Error(w, "Vault engine not configured", http.StatusServiceUnavailable)
		return
	}

	status := cfg.VaultEngine.Status()
	writeJSONResponse(w, http.StatusOK, status)
}

func (cfg *HandlerConfig) handleVaultSecrets(w http.ResponseWriter, r *http.Request) {
	if cfg.VaultEngine == nil {
		http.Error(w, "Vault engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !cfg.authorize(w, r, security.RoleViewer) {
			return
		}
		typeFilter := r.URL.Query().Get("type")
		secrets := cfg.VaultEngine.ListSecrets(typeFilter)
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"secrets": secrets,
			"count":   len(secrets),
		})

	case http.MethodPost:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1048576)) // 1MB limit
		if err != nil {
			http.Error(w, "Failed to read request payload", http.StatusBadRequest)
			return
		}
		var req storeSecretRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		if req.Key == "" || req.Value == "" {
			http.Error(w, "Secret key and value are required", http.StatusBadRequest)
			return
		}
		if req.Type == "" {
			req.Type = vault.SecretTypeGeneric
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		actor := cfg.getActor(r)
		clientIP := getClientIP(r)

		plaintext := []byte(req.Value)
		summary, err := cfg.VaultEngine.StoreSecret(req.Key, req.Type, plaintext, ttl, req.Tags, req.Metadata, actor, clientIP)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSONResponse(w, http.StatusCreated, summary)

	case http.MethodDelete:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			id = r.URL.Query().Get("key")
		}
		if id == "" {
			http.Error(w, "Secret id or key required", http.StatusBadRequest)
			return
		}
		actor := cfg.getActor(r)
		clientIP := getClientIP(r)
		if err := cfg.VaultEngine.DeleteSecret(id, actor, clientIP); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success": true,
			"message": "Secret cryptographically shredded and deleted",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cfg *HandlerConfig) handleVaultReadSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.VaultEngine == nil {
		http.Error(w, "Vault engine not configured", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	idOrKey := q.Get("id")
	if idOrKey == "" {
		idOrKey = q.Get("key")
	}
	if idOrKey == "" {
		http.Error(w, "Secret id or key parameter is required", http.StatusBadRequest)
		return
	}

	issueLease := q.Get("lease") == "true"
	var leaseTTL time.Duration
	if ttlStr := q.Get("ttl"); ttlStr != "" {
		if sec, err := strconv.Atoi(ttlStr); err == nil && sec > 0 {
			leaseTTL = time.Duration(sec) * time.Second
		}
	}

	actor := cfg.getActor(r)
	clientIP := getClientIP(r)

	lease, plaintext, err := cfg.VaultEngine.ReadSecret(idOrKey, issueLease, leaseTTL, actor, clientIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	defer vault.Zeroize(plaintext)

	resp := readSecretResponse{
		Key:       idOrKey,
		Value:     string(plaintext),
		Lease:     lease,
		Timestamp: time.Now().UTC(),
	}
	writeJSONResponse(w, http.StatusOK, resp)
}

func (cfg *HandlerConfig) handleVaultRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.VaultEngine == nil {
		http.Error(w, "Vault engine not configured", http.StatusServiceUnavailable)
		return
	}

	actor := cfg.getActor(r)
	clientIP := getClientIP(r)

	entry, err := cfg.VaultEngine.RotateMasterKey(actor, clientIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]any{
		"success":    true,
		"key_id":     entry.KeyID,
		"state":      entry.State,
		"created_at": entry.CreatedAt,
	})
}

func (cfg *HandlerConfig) handleVaultLeases(w http.ResponseWriter, r *http.Request) {
	if cfg.VaultEngine == nil {
		http.Error(w, "Vault engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !cfg.authorize(w, r, security.RoleViewer) {
			return
		}
		leases := cfg.VaultEngine.ListLeases()
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"leases": leases,
			"count":  len(leases),
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cfg *HandlerConfig) handleVaultLeaseRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.VaultEngine == nil {
		http.Error(w, "Vault engine not configured", http.StatusServiceUnavailable)
		return
	}

	var req renewLeaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.LeaseID == "" {
		http.Error(w, "Invalid JSON: lease_id is required", http.StatusBadRequest)
		return
	}
	if req.ExtendSeconds <= 0 {
		req.ExtendSeconds = 300
	}

	actor := cfg.getActor(r)
	clientIP := getClientIP(r)

	renewed, err := cfg.VaultEngine.RenewLease(req.LeaseID, time.Duration(req.ExtendSeconds)*time.Second, actor, clientIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSONResponse(w, http.StatusOK, renewed)
}

func (cfg *HandlerConfig) handleVaultLeaseRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.VaultEngine == nil {
		http.Error(w, "Vault engine not configured", http.StatusServiceUnavailable)
		return
	}

	var req revokeLeaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.LeaseID == "" {
		http.Error(w, "Invalid JSON: lease_id is required", http.StatusBadRequest)
		return
	}

	actor := cfg.getActor(r)
	clientIP := getClientIP(r)

	revoked, err := cfg.VaultEngine.RevokeLease(req.LeaseID, actor, clientIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"success":  true,
		"lease_id": revoked.LeaseID,
		"message":  "Lease revoked and access shredded",
	})
}

func (cfg *HandlerConfig) handleVaultTokens(w http.ResponseWriter, r *http.Request) {
	if cfg.VaultEngine == nil {
		http.Error(w, "Vault engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !cfg.authorize(w, r, security.RoleViewer) {
			return
		}
		tokens := cfg.VaultEngine.ListJoinTokens()
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"tokens": tokens,
			"count":  len(tokens),
		})

	case http.MethodPost:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		var req createJoinTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		if req.TTLSeconds <= 0 {
			req.TTLSeconds = 3600
		}
		actor := cfg.getActor(r)
		clientIP := getClientIP(r)

		plain, tok, err := cfg.VaultEngine.CreateJoinToken(req.Role, time.Duration(req.TTLSeconds)*time.Second, req.MaxUses, actor, clientIP)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSONResponse(w, http.StatusCreated, createJoinTokenResponse{
			Token:     plain,
			TokenID:   tok.TokenID,
			Role:      tok.NodeRole,
			ExpiresAt: tok.ExpiresAt,
			MaxUses:   tok.MaxUses,
		})

	case http.MethodDelete:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		tokenID := r.URL.Query().Get("id")
		if tokenID == "" {
			http.Error(w, "Token id is required", http.StatusBadRequest)
			return
		}
		actor := cfg.getActor(r)
		clientIP := getClientIP(r)
		if err := cfg.VaultEngine.RevokeJoinToken(tokenID, actor, clientIP); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success": true,
			"message": "Join token revoked",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cfg *HandlerConfig) handleVaultConfig(w http.ResponseWriter, r *http.Request) {
	if cfg.VaultEngine == nil {
		http.Error(w, "Vault engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !cfg.authorize(w, r, security.RoleViewer) {
			return
		}
		c := cfg.VaultEngine.Config()
		if c.ReplicationSecret != "" {
			c.ReplicationSecret = "******"
		}
		writeJSONResponse(w, http.StatusOK, c)

	case http.MethodPost:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		var newCfg vault.VaultConfig
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		actor := cfg.getActor(r)
		clientIP := getClientIP(r)
		if err := cfg.VaultEngine.UpdateConfig(newCfg, actor, clientIP); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success": true,
			"message": "Vault configuration updated",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cfg *HandlerConfig) handleVaultSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.VaultEngine == nil {
		http.Error(w, "Vault engine not configured", http.StatusServiceUnavailable)
		return
	}

	var payload vault.VaultSyncPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	actor := cfg.getActor(r)
	clientIP := getClientIP(r)

	count, err := cfg.VaultEngine.IngestSyncPayload(&payload, actor, clientIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]any{
		"success":  true,
		"ingested": count,
	})
}

func (cfg *HandlerConfig) getActor(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return "bearer-token-client"
	}
	return "local-admin"
}

func getClientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return forwarded
	}
	return ip
}
