package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/querycache"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestQueryCacheHandler() (*HandlerConfig, *http.ServeMux) {
	mux := http.NewServeMux()
	tokenAuth := security.NewTokenAuth("admin-secret", "viewer-secret", true)

	auditLogger := audit.NewLogger(100)
	alertStore := alert.NewConfigStore(alert.DefaultConfig())
	alertDispatcher := alert.NewDispatcher(alertStore)

	engine := querycache.NewEngine(
		querycache.DefaultCacheConfig(),
		querycache.DefaultMultiplexerConfig(),
		querycache.DefaultDedupConfig(),
		auditLogger,
		alertDispatcher,
		nil,
		"test-node",
	)

	cfg := &HandlerConfig{
		AuditLogger:      auditLogger,
		AlertDispatcher:  alertDispatcher,
		QueryCacheEngine: engine,
		TokenAuth:        tokenAuth,
		AllowRemote:      true,
		AppVersion:       "3.0.0",
	}

	mux.HandleFunc("/api/cache/status", cfg.handleCacheStatus)
	mux.HandleFunc("/api/cache/keys", cfg.handleCacheKeys)
	mux.HandleFunc("/api/cache/purge", cfg.handleCachePurge)
	mux.HandleFunc("/api/cache/config", cfg.handleCacheConfig)
	mux.HandleFunc("/api/events/status", cfg.handleEventsStatus)
	mux.HandleFunc("/api/events/stream", cfg.handleEventsStream)
	mux.HandleFunc("/api/events/publish", cfg.handleEventsPublish)
	mux.HandleFunc("/api/events/test", cfg.handleEventsTest)

	return cfg, mux
}

func TestHandleCacheStatus_ViewerAccess(t *testing.T) {
	_, mux := setupTestQueryCacheHandler()

	// 1. Without auth: 401
	req := httptest.NewRequest(http.MethodGet, "/api/cache/status", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rr.Code)
	}

	// 2. With Viewer auth: 200 OK
	req = httptest.NewRequest(http.MethodGet, "/api/cache/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var status querycache.QueryCacheStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to decode status: %v", err)
	}
	if !status.Enabled {
		t.Error("expected cache to be enabled")
	}
}

func TestHandleCacheKeys_ViewerAccess(t *testing.T) {
	cfg, mux := setupTestQueryCacheHandler()
	_ = cfg.QueryCacheEngine.Cache().Set("test:key:1", "data", 10*time.Second)

	req := httptest.NewRequest(http.MethodGet, "/api/cache/keys", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if resp["count"].(float64) < 1 {
		t.Errorf("expected count >= 1, got %v", resp["count"])
	}
}

func TestHandleCachePurge_AdminOnly(t *testing.T) {
	cfg, mux := setupTestQueryCacheHandler()
	_ = cfg.QueryCacheEngine.Cache().Set("docker:c1", "data", 10*time.Second)
	_ = cfg.QueryCacheEngine.Cache().Set("system:m1", "data", 10*time.Second)

	// Viewer cannot purge (403 Forbidden)
	req := httptest.NewRequest(http.MethodPost, "/api/cache/purge", strings.NewReader(`{"prefix":"docker:"}`))
	req.Header.Set("Authorization", "Bearer viewer-secret")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer, got %d", rr.Code)
	}

	// Admin can purge
	req = httptest.NewRequest(http.MethodPost, "/api/cache/purge", strings.NewReader(`{"prefix":"docker:"}`))
	req.Header.Set("Authorization", "Bearer admin-secret")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["purged_count"].(float64) != 1 {
		t.Errorf("expected 1 purged item, got %v", resp["purged_count"])
	}
}

func TestHandleCacheConfig_GetAndPost(t *testing.T) {
	_, mux := setupTestQueryCacheHandler()

	// Get config
	req := httptest.NewRequest(http.MethodGet, "/api/cache/config", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	var cCfg querycache.CacheConfig
	_ = json.Unmarshal(rr.Body.Bytes(), &cCfg)
	if cCfg.MaxItems <= 0 {
		t.Errorf("expected positive max items, got %d", cCfg.MaxItems)
	}

	// Post updated config as Admin
	cCfg.MaxItems = 8000
	payload, _ := json.Marshal(cCfg)
	req = httptest.NewRequest(http.MethodPost, "/api/cache/config", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer admin-secret")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleEventsStatus_ViewerAccess(t *testing.T) {
	_, mux := setupTestQueryCacheHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/events/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if _, ok := resp["multiplexer"]; !ok {
		t.Error("expected multiplexer key in response")
	}
}

func TestHandleEventsPublishAndTest_AdminOnly(t *testing.T) {
	_, mux := setupTestQueryCacheHandler()

	// Test endpoint
	req := httptest.NewRequest(http.MethodPost, "/api/events/test", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for test event, got %d: %s", rr.Code, rr.Body.String())
	}

	// Publish custom event
	pubPayload := `{"type":"container","action":"start","actor_id":"c-999","actor_name":"app"}`
	req = httptest.NewRequest(http.MethodPost, "/api/events/publish", strings.NewReader(pubPayload))
	req.Header.Set("Authorization", "Bearer admin-secret")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for custom publish, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleEventsStream_SSE(t *testing.T) {
	cfg, mux := setupTestQueryCacheHandler()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/api/events/stream", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer viewer-secret")
	rr := httptest.NewRecorder()

	go func() {
		time.Sleep(20 * time.Millisecond)
		cfg.QueryCacheEngine.IngestEvent(querycache.DockerEvent{
			ID:        "sse-e1",
			Action:    "start",
			ActorID:   "c-stream-test",
			ActorName: "streamer",
			Time:      time.Now().Unix(),
		})
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	mux.ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "event: connected") {
		t.Errorf("expected connected SSE event, got:\n%s", body)
	}
	if !strings.Contains(body, "sse-e1") {
		t.Errorf("expected dispatched sse-e1 event in body, got:\n%s", body)
	}
}
