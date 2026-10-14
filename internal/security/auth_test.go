package security

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestTokenAuth_DisabledMode(t *testing.T) {
	// When tokens are empty, auth is disabled
	auth := NewTokenAuth("", "", false)
	if auth.IsEnabled() {
		t.Errorf("Expected auth.IsEnabled() to be false")
	}

	// Loopback request should receive RoleAdmin
	req := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	req.RemoteAddr = "127.0.0.1:45678"

	role := auth.AuthenticateRequest(req)
	if role != RoleAdmin {
		t.Errorf("Expected RoleAdmin for local loopback request, got %v", role)
	}

	// Remote request without allowRemote should receive RoleNone
	remoteReq := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	remoteReq.RemoteAddr = "192.168.1.50:45678"

	remoteRole := auth.AuthenticateRequest(remoteReq)
	if remoteRole != RoleNone {
		t.Errorf("Expected RoleNone for remote request without auth/allowRemote, got %v", remoteRole)
	}

	// Remote request with allowRemoteWithoutAuth should receive RoleAdmin
	authWithRemote := NewTokenAuth("", "", true)
	roleRemoteAllowed := authWithRemote.AuthenticateRequest(remoteReq)
	if roleRemoteAllowed != RoleAdmin {
		t.Errorf("Expected RoleAdmin when allowRemoteWithoutAuth=true, got %v", roleRemoteAllowed)
	}
}

func TestTokenAuth_BearerHeader(t *testing.T) {
	auth := NewTokenAuth("admin-secret-token-12345", "viewer-secret-token-67890", false)
	if !auth.IsEnabled() {
		t.Fatalf("Expected auth to be enabled")
	}

	// Admin Token in Authorization: Bearer
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/docker/restart", nil)
	reqAdmin.Header.Set("Authorization", "Bearer admin-secret-token-12345")
	reqAdmin.RemoteAddr = "10.0.0.5:12345"

	role, err := auth.Authorize(reqAdmin, RoleAdmin)
	if err != nil || role != RoleAdmin {
		t.Errorf("Expected Admin authorization to succeed, got role=%v, err=%v", role, err)
	}

	// Viewer Token in Authorization: Bearer
	reqViewer := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	reqViewer.Header.Set("Authorization", "Bearer viewer-secret-token-67890")
	reqViewer.RemoteAddr = "10.0.0.5:12345"

	role, err = auth.Authorize(reqViewer, RoleViewer)
	if err != nil || role != RoleViewer {
		t.Errorf("Expected Viewer authorization for read endpoint to succeed, got role=%v, err=%v", role, err)
	}

	// Viewer attempting Admin action
	reqViewerAdmin := httptest.NewRequest(http.MethodPost, "/api/docker/stop", nil)
	reqViewerAdmin.Header.Set("Authorization", "Bearer viewer-secret-token-67890")
	reqViewerAdmin.RemoteAddr = "10.0.0.5:12345"

	role, err = auth.Authorize(reqViewerAdmin, RoleAdmin)
	if err != ErrForbidden {
		t.Errorf("Expected ErrForbidden when viewer attempts admin action, got role=%v, err=%v", role, err)
	}
}

func TestTokenAuth_QueryParameterAndApiKey(t *testing.T) {
	auth := NewTokenAuth("super-admin-key", "", false)

	// Token in URL query parameter (critical for WebSockets)
	reqQuery := httptest.NewRequest(http.MethodGet, "/api/docker/logs?id=container1&token=super-admin-key", nil)
	reqQuery.RemoteAddr = "192.168.0.10:3344"

	role := auth.AuthenticateRequest(reqQuery)
	if role != RoleAdmin {
		t.Errorf("Expected RoleAdmin from query parameter token, got %v", role)
	}

	// Token in X-API-Key header
	reqApiKey := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	reqApiKey.Header.Set("X-API-Key", "super-admin-key")
	reqApiKey.RemoteAddr = "192.168.0.10:3344"

	role = auth.AuthenticateRequest(reqApiKey)
	if role != RoleAdmin {
		t.Errorf("Expected RoleAdmin from X-API-Key header, got %v", role)
	}
}

func TestTokenAuth_InvalidOrMissingToken(t *testing.T) {
	auth := NewTokenAuth("admin-token", "viewer-token", false)

	// Missing token on remote connection
	reqEmpty := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	reqEmpty.RemoteAddr = "192.168.0.2:4455"

	_, err := auth.Authorize(reqEmpty, RoleViewer)
	if err != ErrUnauthorized {
		t.Errorf("Expected ErrUnauthorized for missing token, got %v", err)
	}

	// Invalid token
	reqInvalid := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	reqInvalid.Header.Set("Authorization", "Bearer completely-wrong-token")
	reqInvalid.RemoteAddr = "192.168.0.2:4455"

	_, err = auth.Authorize(reqInvalid, RoleViewer)
	if err != ErrUnauthorized {
		t.Errorf("Expected ErrUnauthorized for invalid token, got %v", err)
	}
}

func TestTokenAuth_ConcurrencyAndRotation(t *testing.T) {
	auth := NewTokenAuth("initial-admin", "initial-viewer", false)

	var wg sync.WaitGroup
	workers := 10
	iterations := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if workerID == 0 && j%20 == 0 {
					auth.UpdateTokens("rotated-admin", "rotated-viewer")
				} else {
					role := auth.AuthenticateToken("rotated-admin")
					if role != RoleAdmin && role != RoleNone {
						t.Errorf("Unexpected role during rotation: %v", role)
					}
				}
			}
		}(i)
	}

	wg.Wait()
}
