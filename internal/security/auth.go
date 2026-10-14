package security

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"sync"
)

// Role defines role-based access control tiers.
type Role string

const (
	// RoleAdmin grants full control: container restart/stop, alert rule updates, log streaming, and telemetry inspection.
	RoleAdmin Role = "admin"
	// RoleViewer grants read-only access: telemetry inspection, container listing, log feeds, and alert incident status.
	RoleViewer Role = "viewer"
	// RoleNone represents an unauthenticated or denied principal.
	RoleNone Role = "none"
)

var (
	// ErrUnauthorized denotes missing or invalid credentials.
	ErrUnauthorized = errors.New("authentication required: missing or invalid bearer token")
	// ErrForbidden denotes valid authentication but insufficient privileges for the requested action.
	ErrForbidden = errors.New("access forbidden: insufficient role permissions")
)

// TokenAuth provides thread-safe Bearer token authentication and role-based authorization.
type TokenAuth struct {
	mu                     sync.RWMutex
	adminToken             string
	viewerToken            string
	enabled                bool
	allowRemoteWithoutAuth bool
}

// NewTokenAuth initializes token-based authentication.
// If either adminToken or viewerToken is non-empty, token enforcement is enabled.
func NewTokenAuth(adminToken, viewerToken string, allowRemoteWithoutAuth bool) *TokenAuth {
	admin := strings.TrimSpace(adminToken)
	viewer := strings.TrimSpace(viewerToken)
	enabled := admin != "" || viewer != ""

	return &TokenAuth{
		adminToken:             admin,
		viewerToken:            viewer,
		enabled:                enabled,
		allowRemoteWithoutAuth: allowRemoteWithoutAuth,
	}
}

// IsEnabled returns true if Bearer token authentication is currently active.
func (ta *TokenAuth) IsEnabled() bool {
	ta.mu.RLock()
	defer ta.mu.RUnlock()
	return ta.enabled
}

// UpdateTokens allows runtime rotation of admin and viewer tokens.
func (ta *TokenAuth) UpdateTokens(adminToken, viewerToken string) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	ta.adminToken = strings.TrimSpace(adminToken)
	ta.viewerToken = strings.TrimSpace(viewerToken)
	ta.enabled = ta.adminToken != "" || ta.viewerToken != ""
}

// ExtractToken retrieves the bearer credential from the Authorization header,
// X-API-Key header, or URL query parameter ("token").
func ExtractToken(r *http.Request) string {
	// 1. Authorization: Bearer <token>
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
	}

	// 2. X-API-Key header fallback
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return strings.TrimSpace(apiKey)
	}

	// 3. Query parameter fallback (essential for browser WebSocket handshakes)
	if tokenQuery := r.URL.Query().Get("token"); tokenQuery != "" {
		return strings.TrimSpace(tokenQuery)
	}

	return ""
}

// AuthenticateToken matches a raw token string against configured tokens in constant time.
func (ta *TokenAuth) AuthenticateToken(token string) Role {
	ta.mu.RLock()
	defer ta.mu.RUnlock()

	if token == "" {
		return RoleNone
	}

	tokenBytes := []byte(token)

	// Constant-time admin comparison
	if ta.adminToken != "" {
		adminBytes := []byte(ta.adminToken)
		if subtle.ConstantTimeCompare(tokenBytes, adminBytes) == 1 {
			return RoleAdmin
		}
	}

	// Constant-time viewer comparison
	if ta.viewerToken != "" {
		viewerBytes := []byte(ta.viewerToken)
		if subtle.ConstantTimeCompare(tokenBytes, viewerBytes) == 1 {
			return RoleViewer
		}
	}

	return RoleNone
}

// AuthenticateRequest inspects the HTTP request and resolves the caller's role.
func (ta *TokenAuth) AuthenticateRequest(r *http.Request) Role {
	ta.mu.RLock()
	enabled := ta.enabled
	allowRemote := ta.allowRemoteWithoutAuth
	ta.mu.RUnlock()

	token := ExtractToken(r)

	// If a token was provided, evaluate it regardless of loopback or remote state
	if token != "" {
		return ta.AuthenticateToken(token)
	}

	// When authentication is not enabled:
	if !enabled {
		// Loopback clients are automatically trusted as local admin
		remoteHost := r.RemoteAddr
		if host, _, err := netSplitHost(remoteHost); err == nil {
			remoteHost = host
		}
		if IsLoopbackHost(remoteHost) || allowRemote {
			return RoleAdmin
		}
		return RoleNone
	}

	// If auth is enabled but no token was provided:
	// Local loopback is only granted read-only viewer if loopback, or none
	remoteHost := r.RemoteAddr
	if host, _, err := netSplitHost(remoteHost); err == nil {
		remoteHost = host
	}
	if IsLoopbackHost(remoteHost) && ta.adminToken == "" && ta.viewerToken != "" {
		return RoleViewer
	}

	return RoleNone
}

// HasPermission verifies if the granted role satisfies the required role.
func HasPermission(granted, required Role) bool {
	if granted == RoleAdmin {
		return true // Admin satisfies all permissions
	}
	if granted == RoleViewer && required == RoleViewer {
		return true
	}
	return false
}

// Authorize validates that the caller satisfies the specified minimum role.
func (ta *TokenAuth) Authorize(r *http.Request, required Role) (Role, error) {
	role := ta.AuthenticateRequest(r)
	if role == RoleNone {
		return RoleNone, ErrUnauthorized
	}
	if !HasPermission(role, required) {
		return role, ErrForbidden
	}
	return role, nil
}

func netSplitHost(addr string) (string, string, error) {
	idx := strings.LastIndex(addr, ":")
	if idx == -1 {
		return addr, "", nil
	}
	return addr[:idx], addr[idx+1:], nil
}
