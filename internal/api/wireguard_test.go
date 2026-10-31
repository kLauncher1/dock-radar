package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/security"
	"github.com/kLauncher1/dock-radar/internal/wireguard"
)

func setupTestWireGuardHandler(t *testing.T) (*HandlerConfig, *http.ServeMux) {
	mux := http.NewServeMux()
	logger := audit.NewLogger(50)
	engine, err := wireguard.NewEngine(wireguard.DefaultWireGuardConfig(), logger, nil)
	if err != nil {
		t.Fatalf("failed to create wireguard engine: %v", err)
	}

	auth := security.NewTokenAuth("admin-secret-token-1234", "viewer-secret-token-1234", true)

	cfg := &HandlerConfig{
		WireGuardEngine: engine,
		TokenAuth:       auth,
		RateLimiter:     security.NewRateLimiter(10, 10),
	}

	mux.HandleFunc("/api/wireguard/status", cfg.handleWireGuardStatus)
	mux.HandleFunc("/api/wireguard/peers", cfg.handleWireGuardPeers)
	mux.HandleFunc("/api/wireguard/handshake", cfg.handleWireGuardHandshake)
	mux.HandleFunc("/api/wireguard/leases", cfg.handleWireGuardLeases)
	mux.HandleFunc("/api/wireguard/leases/reclaim", cfg.handleWireGuardReclaimLeases)
	mux.HandleFunc("/api/wireguard/routes", cfg.handleWireGuardRoutes)
	mux.HandleFunc("/api/wireguard/keygen", cfg.handleWireGuardKeygen)
	mux.HandleFunc("/api/wireguard/config", cfg.handleWireGuardConfig)

	return cfg, mux
}

func TestHandleWireGuardStatus(t *testing.T) {
	_, mux := setupTestWireGuardHandler(t)

	// Unauthorized request
	req := httptest.NewRequest(http.MethodGet, "/api/wireguard/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
	}

	// Authorized with Viewer token
	req = httptest.NewRequest(http.MethodGet, "/api/wireguard/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token-1234")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var status wireguard.WireGuardStatus
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !status.Enabled || status.ListenPort != 51820 {
		t.Errorf("unexpected status content: %+v", status)
	}
}

func TestHandleWireGuardPeers_CRUD(t *testing.T) {
	_, mux := setupTestWireGuardHandler(t)

	keys, _ := wireguard.GenerateKeyPair()
	peerPayload := wireguard.PeerConfig{
		ID:        "peer-gateway-1",
		Name:      "Tokyo Gateway",
		PublicKey: keys.PublicKeyBase64,
		Endpoint:  "203.0.113.15:51820",
	}
	body, _ := json.Marshal(peerPayload)

	// Add peer as Viewer -> forbidden (requires Admin)
	req := httptest.NewRequest(http.MethodPost, "/api/wireguard/peers", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer viewer-secret-token-1234")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for Viewer on POST /peers, got %d", rec.Code)
	}

	// Add peer as Admin -> created
	req = httptest.NewRequest(http.MethodPost, "/api/wireguard/peers", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-secret-token-1234")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on POST /peers, got %d", rec.Code)
	}

	// List peers as Viewer -> OK
	req = httptest.NewRequest(http.MethodGet, "/api/wireguard/peers", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token-1234")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on GET /peers, got %d", rec.Code)
	}

	var peers []wireguard.PeerConfig
	_ = json.NewDecoder(rec.Body).Decode(&peers)
	if len(peers) != 1 || peers[0].ID != "peer-gateway-1" {
		t.Errorf("expected 1 peer named peer-gateway-1, got %+v", peers)
	}

	// Delete peer as Admin -> OK
	req = httptest.NewRequest(http.MethodDelete, "/api/wireguard/peers?id=peer-gateway-1", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token-1234")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK on DELETE /peers, got %d", rec.Code)
	}
}

func TestHandleWireGuardHandshakeAndKeygen(t *testing.T) {
	cfg, mux := setupTestWireGuardHandler(t)

	keys, _ := wireguard.GenerateKeyPair()
	_, _ = cfg.WireGuardEngine.AddPeer(wireguard.PeerConfig{
		ID:        "peer-hs-test",
		PublicKey: keys.PublicKeyBase64,
	})

	// Handshake trigger as Admin
	hsBody, _ := json.Marshal(wireguardHandshakeRequest{PeerID: "peer-hs-test"})
	req := httptest.NewRequest(http.MethodPost, "/api/wireguard/handshake", bytes.NewReader(hsBody))
	req.Header.Set("Authorization", "Bearer admin-secret-token-1234")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on handshake, got %d", rec.Code)
	}

	// Keygen as Admin
	req = httptest.NewRequest(http.MethodPost, "/api/wireguard/keygen", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token-1234")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on keygen, got %d", rec.Code)
	}

	var kgResp wireguardKeygenResponse
	if err := json.NewDecoder(rec.Body).Decode(&kgResp); err != nil {
		t.Fatal(err)
	}
	if kgResp.PublicKey == "" || kgResp.PrivateKey == "" || kgResp.PresharedKey == "" {
		t.Errorf("incomplete keygen response: %+v", kgResp)
	}
}

func TestHandleWireGuardLeasesAndRoutes(t *testing.T) {
	cfg, mux := setupTestWireGuardHandler(t)

	keys, _ := wireguard.GenerateKeyPair()
	_, _ = cfg.WireGuardEngine.AddPeer(wireguard.PeerConfig{
		ID:        "peer-lease-test",
		PublicKey: keys.PublicKeyBase64,
	})

	// GET /leases as Viewer
	req := httptest.NewRequest(http.MethodGet, "/api/wireguard/leases", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token-1234")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /leases, got %d", rec.Code)
	}

	var leases []wireguard.IPLease
	_ = json.NewDecoder(rec.Body).Decode(&leases)
	if len(leases) != 1 {
		t.Errorf("expected 1 active lease, got %d", len(leases))
	}

	// GET /routes as Viewer
	req = httptest.NewRequest(http.MethodGet, "/api/wireguard/routes", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token-1234")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /routes, got %d", rec.Code)
	}

	// POST /leases/reclaim as Admin
	req = httptest.NewRequest(http.MethodPost, "/api/wireguard/leases/reclaim", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token-1234")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /leases/reclaim, got %d", rec.Code)
	}

	// GET /config as Viewer
	req = httptest.NewRequest(http.MethodGet, "/api/wireguard/config", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token-1234")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /config, got %d", rec.Code)
	}
}
