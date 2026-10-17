package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/federation"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestFederationAPI(t *testing.T) (*HandlerConfig, *http.ServeMux) {
	mux := http.NewServeMux()
	tokenAuth := security.NewTokenAuth("admin-secret-token", "viewer-secret-token", false)
	cfg := RegisterRoutesWithSecurity(mux, nil, nil, tokenAuth, false)

	fedCfg := federation.DefaultFederationConfig()
	fedCfg.LocalRegionID = "test-local-region"
	fedCfg.TunnelKey = "shared-tunnel-key-for-api-tests"

	fedEngine, err := federation.NewEngine(fedCfg, nil, cfg.AuditLogger, cfg.AlertDispatcher)
	if err != nil {
		t.Fatalf("failed to create federation engine: %v", err)
	}
	cfg.FederationEngine = fedEngine
	return cfg, mux
}

func TestHandleFederationStatus(t *testing.T) {
	_, mux := setupTestFederationAPI(t)

	// Unauthorized request
	req := httptest.NewRequest(http.MethodGet, "/api/federation/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthorized, got %d", w.Code)
	}

	// Authorized viewer request
	req = httptest.NewRequest(http.MethodGet, "/api/federation/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp FederationStatusResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.LocalRegionID != "test-local-region" {
		t.Fatalf("unexpected local region id: %s", resp.Status.LocalRegionID)
	}
}

func TestHandleFederationRegions_CRUD(t *testing.T) {
	_, mux := setupTestFederationAPI(t)

	// 1. Register region via POST (Admin only)
	newRegion := federation.Region{
		ID:        "eu-west-1",
		Name:      "EU Ireland",
		Endpoint:  "https://eu.dockradar.net",
		Latitude:  53.3,
		Longitude: -6.2,
	}
	body, _ := json.Marshal(newRegion)

	// Forbidden for Viewer
	req := httptest.NewRequest(http.MethodPost, "/api/federation/regions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 forbidden for viewer, got %d", w.Code)
	}

	// Success for Admin
	req = httptest.NewRequest(http.MethodPost, "/api/federation/regions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for admin, got %d: %s", w.Code, w.Body.String())
	}

	// 2. List regions via GET
	req = httptest.NewRequest(http.MethodGet, "/api/federation/regions", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var regionsResp FederationRegionsResponse
	if err := json.NewDecoder(w.Body).Decode(&regionsResp); err != nil {
		t.Fatalf("failed to decode regions list: %v", err)
	}
	if regionsResp.TotalCount != 2 {
		t.Fatalf("expected 2 regions, got %d", regionsResp.TotalCount)
	}

	// 3. Delete region via DELETE (Admin only)
	req = httptest.NewRequest(http.MethodDelete, "/api/federation/regions?id=eu-west-1", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for delete, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleFederationRoutesAndFailover(t *testing.T) {
	_, mux := setupTestFederationAPI(t)

	// 1. Register route (Admin)
	newRoute := federation.ContainerRoute{
		TargetID:        "auth-api",
		ServiceName:     "Auth API Service",
		PrimaryRegion:   "test-local-region",
		FallbackRegions: []string{"eu-west-1"},
	}
	body, _ := json.Marshal(newRoute)

	req := httptest.NewRequest(http.MethodPost, "/api/federation/routes", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for route register, got %d: %s", w.Code, w.Body.String())
	}

	// 2. List routes (Viewer)
	req = httptest.NewRequest(http.MethodGet, "/api/federation/routes", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var routesResp FederationRoutesResponse
	_ = json.NewDecoder(w.Body).Decode(&routesResp)
	if routesResp.TotalCount != 1 {
		t.Fatalf("expected 1 route, got %d", routesResp.TotalCount)
	}

	// 3. Trigger manual failover (Admin)
	failoverReq := FailoverRequest{
		TargetID:     "auth-api",
		TargetRegion: "eu-west-1",
		Reason:       "Maintenance drill",
	}
	foBody, _ := json.Marshal(failoverReq)

	req = httptest.NewRequest(http.MethodPost, "/api/federation/failover", bytes.NewReader(foBody))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on failover, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleFederationConfig(t *testing.T) {
	_, mux := setupTestFederationAPI(t)

	// GET config
	req := httptest.NewRequest(http.MethodGet, "/api/federation/config", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on get config, got %d", w.Code)
	}

	var curCfg federation.FederationConfig
	_ = json.NewDecoder(w.Body).Decode(&curCfg)
	if curCfg.LocalRegionID != "test-local-region" {
		t.Fatalf("unexpected local region id: %s", curCfg.LocalRegionID)
	}

	// POST update config
	curCfg.SyncIntervalSec = 45
	updateBody, _ := json.Marshal(curCfg)

	req = httptest.NewRequest(http.MethodPost, "/api/federation/config", bytes.NewReader(updateBody))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on post config, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleFederationSync_Roundtrip(t *testing.T) {
	cfg, mux := setupTestFederationAPI(t)

	// Create test packet from external region
	delta := &federation.DeltaSyncPayload{
		SenderRegion: "eu-west-1",
		TargetRegion: "test-local-region",
		Digest:       federation.InventoryDigest{RegionID: "eu-west-1", DigestHex: "abc123"},
		Added: []federation.FederatedContainer{
			{ID: "c-remote-1", Name: "remote-worker", State: "running"},
		},
	}
	packet, err := cfg.FederationEngine.TunnelManager().WrapPayload("test-local-region", delta)
	if err != nil {
		t.Fatalf("wrap payload failed: %v", err)
	}

	packetBody, _ := json.Marshal(packet)
	req := httptest.NewRequest(http.MethodPost, "/api/federation/sync", bytes.NewReader(packetBody))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on sync ingest, got %d: %s", w.Code, w.Body.String())
	}

	var respPacket federation.EncryptedPacket
	if err := json.NewDecoder(w.Body).Decode(&respPacket); err != nil {
		t.Fatalf("failed to decode response packet: %v", err)
	}
	if respPacket.SenderRegion != "test-local-region" || respPacket.TargetRegion != "eu-west-1" {
		t.Fatalf("unexpected response packet routing: %+v", respPacket)
	}
}
