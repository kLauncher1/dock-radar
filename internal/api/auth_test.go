package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func TestAuthStatusEndpoint_Disabled(t *testing.T) {
	mux := http.NewServeMux()
	cfg := RegisterRoutes(mux, docker.NewClient(), nil)
	if cfg == nil {
		t.Fatalf("Failed to initialize routes")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req.RemoteAddr = "127.0.0.1:9090"
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rec.Code)
	}

	var status AuthStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if status.Enabled {
		t.Errorf("Expected auth enabled to be false")
	}
	if status.Role != security.RoleAdmin {
		t.Errorf("Expected loopback role to be admin, got %v", status.Role)
	}
}

func TestAuthStatusEndpoint_Enabled(t *testing.T) {
	mux := http.NewServeMux()
	tokenAuth := security.NewTokenAuth("admin-secret", "viewer-secret", false)
	cfg := RegisterRoutesWithSecurity(mux, docker.NewClient(), nil, tokenAuth, false)
	if cfg == nil {
		t.Fatalf("Failed to initialize routes")
	}

	// Unauthenticated request
	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req.RemoteAddr = "10.0.0.1:8888"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var status AuthStatusResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &status)
	if !status.Enabled {
		t.Errorf("Expected auth enabled to be true")
	}
	if status.Authenticated {
		t.Errorf("Expected authenticated=false for missing token")
	}
	if !status.RequiresToken {
		t.Errorf("Expected requires_token=true")
	}

	// Authenticated request with Bearer token
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	reqAuth.Header.Set("Authorization", "Bearer admin-secret")
	recAuth := httptest.NewRecorder()
	mux.ServeHTTP(recAuth, reqAuth)

	var statusAuth AuthStatusResponse
	_ = json.Unmarshal(recAuth.Body.Bytes(), &statusAuth)
	if !statusAuth.Authenticated || statusAuth.Role != security.RoleAdmin {
		t.Errorf("Expected authenticated admin, got %+v", statusAuth)
	}
}

func TestAuthVerifyEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	tokenAuth := security.NewTokenAuth("valid-admin-token", "valid-viewer-token", false)
	RegisterRoutesWithSecurity(mux, docker.NewClient(), nil, tokenAuth, false)

	// 1. Verify Admin Token
	bodyAdmin, _ := json.Marshal(AuthVerifyRequest{Token: "valid-admin-token"})
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/auth/verify", bytes.NewReader(bodyAdmin))
	reqAdmin.Header.Set("Content-Type", "application/json")
	recAdmin := httptest.NewRecorder()
	mux.ServeHTTP(recAdmin, reqAdmin)

	if recAdmin.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", recAdmin.Code)
	}
	var resAdmin AuthVerifyResponse
	_ = json.Unmarshal(recAdmin.Body.Bytes(), &resAdmin)
	if !resAdmin.Valid || resAdmin.Role != security.RoleAdmin {
		t.Errorf("Expected valid admin, got %+v", resAdmin)
	}

	// 2. Verify Viewer Token
	bodyViewer, _ := json.Marshal(AuthVerifyRequest{Token: "valid-viewer-token"})
	reqViewer := httptest.NewRequest(http.MethodPost, "/api/auth/verify", bytes.NewReader(bodyViewer))
	reqViewer.Header.Set("Content-Type", "application/json")
	recViewer := httptest.NewRecorder()
	mux.ServeHTTP(recViewer, reqViewer)

	var resViewer AuthVerifyResponse
	_ = json.Unmarshal(recViewer.Body.Bytes(), &resViewer)
	if !resViewer.Valid || resViewer.Role != security.RoleViewer {
		t.Errorf("Expected valid viewer, got %+v", resViewer)
	}

	// 3. Verify Invalid Token
	bodyInvalid, _ := json.Marshal(AuthVerifyRequest{Token: "wrong-token"})
	reqInvalid := httptest.NewRequest(http.MethodPost, "/api/auth/verify", bytes.NewReader(bodyInvalid))
	reqInvalid.Header.Set("Content-Type", "application/json")
	recInvalid := httptest.NewRecorder()
	mux.ServeHTTP(recInvalid, reqInvalid)

	if recInvalid.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for wrong token, got %d", recInvalid.Code)
	}
}

func TestProtectedEndpoints_WithTokenAuth(t *testing.T) {
	mux := http.NewServeMux()
	tokenAuth := security.NewTokenAuth("secret-admin-key", "secret-viewer-key", false)
	RegisterRoutesWithSecurity(mux, docker.NewClient(), nil, tokenAuth, false)

	// 1. Unauthenticated request to /api/system should be rejected (401)
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	reqUnauth.RemoteAddr = "192.168.1.100:1234"
	recUnauth := httptest.NewRecorder()
	mux.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for unauthenticated /api/system, got %d", recUnauth.Code)
	}

	// 2. Viewer token accesses /api/system (200 OK)
	reqViewer := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	reqViewer.Header.Set("Authorization", "Bearer secret-viewer-key")
	reqViewer.RemoteAddr = "192.168.1.100:1234"
	recViewer := httptest.NewRecorder()
	mux.ServeHTTP(recViewer, reqViewer)
	if recViewer.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for viewer on /api/system, got %d", recViewer.Code)
	}

	// 3. Viewer token attempts mutating restart -> 403 Forbidden
	bodyRestart, _ := json.Marshal(ActionRequest{ID: "test-container"})
	reqViewerRestart := httptest.NewRequest(http.MethodPost, "/api/docker/restart", bytes.NewReader(bodyRestart))
	reqViewerRestart.Header.Set("Authorization", "Bearer secret-viewer-key")
	reqViewerRestart.Header.Set("Content-Type", "application/json")
	reqViewerRestart.RemoteAddr = "192.168.1.100:1234"
	recViewerRestart := httptest.NewRecorder()
	mux.ServeHTTP(recViewerRestart, reqViewerRestart)
	if recViewerRestart.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for viewer on /api/docker/restart, got %d", recViewerRestart.Code)
	}

	// 4. Admin token attempts mutating restart -> authorized (attempts docker call)
	reqAdminRestart := httptest.NewRequest(http.MethodPost, "/api/docker/restart", bytes.NewReader(bodyRestart))
	reqAdminRestart.Header.Set("Authorization", "Bearer secret-admin-key")
	reqAdminRestart.Header.Set("Content-Type", "application/json")
	reqAdminRestart.RemoteAddr = "192.168.1.100:1234"
	recAdminRestart := httptest.NewRecorder()
	mux.ServeHTTP(recAdminRestart, reqAdminRestart)
	// Because docker daemon is offline in unit test, it returns 502/500 rather than 401/403
	if recAdminRestart.Code == http.StatusUnauthorized || recAdminRestart.Code == http.StatusForbidden {
		t.Errorf("Admin should have bypassed auth gate, got %d", recAdminRestart.Code)
	}
}
