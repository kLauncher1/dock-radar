package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/ratelimit"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestRateLimitHandler() (*HandlerConfig, *http.ServeMux) {
	mux := http.NewServeMux()
	handlerCfg := RegisterRoutes(mux, nil, nil)
	return handlerCfg, mux
}

func TestHandleRateLimitStatus(t *testing.T) {
	_, mux := setupTestRateLimitHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/ratelimit/status", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp RateLimitStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Status.Enabled {
		t.Fatalf("expected rate limiter to be enabled by default")
	}
}

func TestHandleRateLimitTenants_CRUD(t *testing.T) {
	_, mux := setupTestRateLimitHandler()

	// 1. Initial list should be empty
	req := httptest.NewRequest(http.MethodGet, "/api/ratelimit/tenants", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	// 2. Create tenant quota
	tenant := ratelimit.TenantQuota{
		TenantID:          "tenant-beta",
		Name:              "Beta Team",
		Tier:              "Enterprise",
		RequestsPerSecond: 100,
		BurstCapacity:     200,
		WindowSeconds:     60,
		MaxBytesPerSecond: 1048576,
	}
	payload, _ := json.Marshal(tenant)
	postReq := httptest.NewRequest(http.MethodPost, "/api/ratelimit/tenants", bytes.NewReader(payload))
	postReq.RemoteAddr = "127.0.0.1:50000"
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on create, got %d (body: %s)", postRec.Code, postRec.Body.String())
	}

	// 3. List should now contain tenant-beta
	listReq := httptest.NewRequest(http.MethodGet, "/api/ratelimit/tenants", nil)
	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, listReq)

	var listResp TenantQuotasResponse
	_ = json.Unmarshal(listRec.Body.Bytes(), &listResp)
	if listResp.TotalCount != 1 || listResp.Tenants[0].TenantID != "tenant-beta" {
		t.Fatalf("expected 1 tenant 'tenant-beta', got %d", listResp.TotalCount)
	}

	// 4. Delete tenant quota
	delReq := httptest.NewRequest(http.MethodDelete, "/api/ratelimit/tenants?id=tenant-beta", nil)
	delReq.RemoteAddr = "127.0.0.1:50000"
	delRec := httptest.NewRecorder()
	mux.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on delete, got %d", delRec.Code)
	}

	// 5. Verify deletion
	listReq2 := httptest.NewRequest(http.MethodGet, "/api/ratelimit/tenants", nil)
	listRec2 := httptest.NewRecorder()
	mux.ServeHTTP(listRec2, listReq2)
	var listResp2 TenantQuotasResponse
	_ = json.Unmarshal(listRec2.Body.Bytes(), &listResp2)
	if listResp2.TotalCount != 0 {
		t.Fatalf("expected 0 tenants after deletion, got %d", listResp2.TotalCount)
	}
}

func TestHandleRateLimitBans_CRUD(t *testing.T) {
	_, mux := setupTestRateLimitHandler()

	// 1. Manually ban an IP
	banReqBody := BanIPRequest{
		IP:              "198.51.100.99",
		Reason:          "Malicious scanner test",
		DurationSeconds: 600,
	}
	payload, _ := json.Marshal(banReqBody)
	postReq := httptest.NewRequest(http.MethodPost, "/api/ratelimit/bans", bytes.NewReader(payload))
	postReq.RemoteAddr = "127.0.0.1:50000"
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on ban, got %d (body: %s)", postRec.Code, postRec.Body.String())
	}

	// 2. Query bans list
	getReq := httptest.NewRequest(http.MethodGet, "/api/ratelimit/bans", nil)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)

	var bansResp BannedIPsResponse
	_ = json.Unmarshal(getRec.Body.Bytes(), &bansResp)
	if bansResp.TotalCount != 1 || bansResp.Bans[0].IP != "198.51.100.99" {
		t.Fatalf("expected 1 ban for 198.51.100.99, got %d", bansResp.TotalCount)
	}

	// 3. Unban the IP
	delReq := httptest.NewRequest(http.MethodDelete, "/api/ratelimit/bans?ip=198.51.100.99", nil)
	delReq.RemoteAddr = "127.0.0.1:50000"
	delRec := httptest.NewRecorder()
	mux.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on unban, got %d", delRec.Code)
	}

	// 4. Verify unbanned
	getReq2 := httptest.NewRequest(http.MethodGet, "/api/ratelimit/bans", nil)
	getRec2 := httptest.NewRecorder()
	mux.ServeHTTP(getRec2, getReq2)
	var bansResp2 BannedIPsResponse
	_ = json.Unmarshal(getRec2.Body.Bytes(), &bansResp2)
	if bansResp2.TotalCount != 0 {
		t.Fatalf("expected 0 active bans, got %d", bansResp2.TotalCount)
	}
}

func TestHandleRateLimitSync(t *testing.T) {
	handlerCfg, mux := setupTestRateLimitHandler()

	secret := "test-sync-secret"
	cfg := handlerCfg.RateLimitEngine.Config()
	cfg.SyncSecret = secret
	_ = handlerCfg.RateLimitEngine.UpdateConfig(cfg)

	// Build a valid sync payload
	bans := []*ratelimit.IPBanRecord{
		{
			IP:         "203.0.113.88",
			Reason:     "Distributed abuse",
			OriginNode: "peer-east",
			ExpiresAt:  time.Now().Add(10 * time.Minute),
		},
	}
	syncPayload, err := ratelimit.BuildSyncPayload("peer-east", secret, bans)
	if err != nil {
		t.Fatalf("failed to build sync payload: %v", err)
	}

	body, _ := json.Marshal(syncPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/ratelimit/sync", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on sync, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var syncResp SyncResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &syncResp)
	if !syncResp.Success || syncResp.AppliedBans != 1 {
		t.Fatalf("expected 1 applied ban, got %+v", syncResp)
	}
}

func TestHandleRateLimitConfig(t *testing.T) {
	_, mux := setupTestRateLimitHandler()

	// GET config
	getReq := httptest.NewRequest(http.MethodGet, "/api/ratelimit/config", nil)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", getRec.Code)
	}

	// POST config update
	newCfg := ratelimit.LimiterConfig{
		Enabled:                true,
		DefaultRPS:             75.0,
		DefaultBurst:           150,
		BanThresholdViolations: 15,
		BanDurationSeconds:     1200,
	}
	body, _ := json.Marshal(newCfg)
	postReq := httptest.NewRequest(http.MethodPost, "/api/ratelimit/config", bytes.NewReader(body))
	postReq.RemoteAddr = "127.0.0.1:50000"
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on config update, got %d", postRec.Code)
	}
}

func TestHandleRateLimit_AuthRBAC(t *testing.T) {
	mux := http.NewServeMux()
	tokenAuth := security.NewTokenAuth("admin-secret-token", "viewer-secret-token", false)

	_ = RegisterRoutesWithSecurity(mux, nil, nil, tokenAuth, false)

	// Unauthenticated request to /api/ratelimit/status should fail 401
	req := httptest.NewRequest(http.MethodGet, "/api/ratelimit/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthorized, got %d", rec.Code)
	}

	// Viewer token to /api/ratelimit/status should pass 200
	reqViewer := httptest.NewRequest(http.MethodGet, "/api/ratelimit/status", nil)
	reqViewer.Header.Set("Authorization", "Bearer viewer-secret-token")
	recViewer := httptest.NewRecorder()
	mux.ServeHTTP(recViewer, reqViewer)

	if recViewer.Code != http.StatusOK {
		t.Fatalf("expected 200 with viewer token, got %d", recViewer.Code)
	}

	// Viewer token to mutation /api/ratelimit/tenants should fail 403 Forbidden
	reqMutate := httptest.NewRequest(http.MethodPost, "/api/ratelimit/tenants", bytes.NewReader([]byte("{}")))
	reqMutate.Header.Set("Authorization", "Bearer viewer-secret-token")
	recMutate := httptest.NewRecorder()
	mux.ServeHTTP(recMutate, reqMutate)

	if recMutate.Code != http.StatusForbidden {
		t.Fatalf("expected 403 forbidden for viewer mutation, got %d", recMutate.Code)
	}
}
