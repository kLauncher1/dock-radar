package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/security"
)

// AuthStatusResponse communicates authentication states and client roles to the web UI.
type AuthStatusResponse struct {
	Enabled        bool          `json:"enabled"`
	Role           security.Role `json:"role"`
	Authenticated  bool          `json:"authenticated"`
	TLS            bool          `json:"tls"`
	RemoteAllowed  bool          `json:"remote_allowed"`
	RequiresToken  bool          `json:"requires_token"`
}

// AuthVerifyRequest parses token verification payloads from clients.
type AuthVerifyRequest struct {
	Token string `json:"token"`
}

// AuthVerifyResponse reports validation outcomes for user-entered credentials.
type AuthVerifyResponse struct {
	Valid   bool          `json:"valid"`
	Role    security.Role `json:"role"`
	Message string        `json:"message"`
}

func (h *HandlerConfig) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	enabled := false
	var role security.Role = security.RoleAdmin
	if h.TokenAuth != nil {
		enabled = h.TokenAuth.IsEnabled()
		role = h.TokenAuth.AuthenticateRequest(r)
	}

	isTLS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	authenticated := role == security.RoleAdmin || role == security.RoleViewer
	requiresToken := enabled && !authenticated

	resp := AuthStatusResponse{
		Enabled:       enabled,
		Role:          role,
		Authenticated: authenticated,
		TLS:           isTLS,
		RemoteAllowed: h.AllowRemote,
		RequiresToken: requiresToken,
	}

	_ = json.NewEncoder(w).Encode(resp)
}

func (h *HandlerConfig) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req AuthVerifyRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err == nil && len(body) > 0 {
		_ = json.Unmarshal(body, &req)
	}

	token := strings.TrimSpace(req.Token)
	if token == "" {
		token = security.ExtractToken(r)
	}

	if h.TokenAuth == nil || !h.TokenAuth.IsEnabled() {
		_ = json.NewEncoder(w).Encode(AuthVerifyResponse{
			Valid:   true,
			Role:    security.RoleAdmin,
			Message: "Authentication not enabled; local administrator access granted.",
		})
		return
	}

	role := h.TokenAuth.AuthenticateToken(token)
	if role == security.RoleNone {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(AuthVerifyResponse{
			Valid:   false,
			Role:    security.RoleNone,
			Message: "Invalid authentication token.",
		})
		return
	}

	_ = json.NewEncoder(w).Encode(AuthVerifyResponse{
		Valid:   true,
		Role:    role,
		Message: "Authentication successful.",
	})
}
