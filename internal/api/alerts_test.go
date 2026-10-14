package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupAlertTestServer() (*http.ServeMux, *httptest.Server, *HandlerConfig) {
	mockDaemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.43/containers/json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":"c12345678901","names":["/web"],"image":"nginx:alpine","state":"running","status":"Up 2 hours"}]`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	dockerClient := docker.NewCustomClient(mockDaemon.Client(), mockDaemon.URL)
	mux := http.NewServeMux()
	cfg := RegisterRoutes(mux, dockerClient, nil)
	return mux, mockDaemon, cfg
}

func TestAlertConfig_GetAndPost(t *testing.T) {
	mux, mockDaemon, _ := setupAlertTestServer()
	defer mockDaemon.Close()

	// 1. GET /api/alerts/config
	reqGet := httptest.NewRequest(http.MethodGet, "/api/alerts/config", nil)
	recGet := httptest.NewRecorder()
	mux.ServeHTTP(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on GET /api/alerts/config, got %d", recGet.Code)
	}

	var cfg alert.Config
	if err := json.NewDecoder(recGet.Body).Decode(&cfg); err != nil {
		t.Fatalf("failed to decode alert config: %v", err)
	}
	if cfg.Enabled {
		t.Errorf("expected default Enabled to be false")
	}
	if cfg.CPUThresholdPercent != 85.0 {
		t.Errorf("expected default CPU threshold 85.0, got %f", cfg.CPUThresholdPercent)
	}

	// 2. POST /api/alerts/config (Valid update)
	newCfg := alert.Config{
		Enabled:               true,
		DiscordWebhookURL:     "https://discord.com/api/webhooks/999/xyz",
		SlackWebhookURL:       "https://hooks.slack.com/services/T01/B01/XYZ",
		CPUThresholdPercent:   92.0,
		MemoryThresholdMB:     750.0,
		RestartThresholdCount: 4,
		FlappingWindowSeconds: 240,
		CooldownSeconds:       90,
	}
	bodyBytes, _ := json.Marshal(newCfg)
	reqPost := httptest.NewRequest(http.MethodPost, "/api/alerts/config", bytes.NewReader(bodyBytes))
	reqPost.Header.Set("Content-Type", "application/json")
	reqPost.RemoteAddr = "127.0.0.1:45000"
	recPost := httptest.NewRecorder()
	mux.ServeHTTP(recPost, reqPost)

	if recPost.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on POST /api/alerts/config, got %d: %s", recPost.Code, recPost.Body.String())
	}

	var updatedCfg alert.Config
	if err := json.NewDecoder(recPost.Body).Decode(&updatedCfg); err != nil {
		t.Fatalf("failed to decode updated config: %v", err)
	}
	if !updatedCfg.Enabled {
		t.Errorf("expected Enabled to be true after update")
	}
	if updatedCfg.CPUThresholdPercent != 92.0 {
		t.Errorf("expected CPUThresholdPercent 92.0, got %f", updatedCfg.CPUThresholdPercent)
	}

	// 3. POST /api/alerts/config with non-loopback origin (Should be 403 Forbidden)
	reqRemote := httptest.NewRequest(http.MethodPost, "/api/alerts/config", bytes.NewReader(bodyBytes))
	reqRemote.Header.Set("Content-Type", "application/json")
	reqRemote.RemoteAddr = "192.168.1.100:50000"
	recRemote := httptest.NewRecorder()
	mux.ServeHTTP(recRemote, reqRemote)

	if recRemote.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 for remote address, got %d", recRemote.Code)
	}

	// 4. POST /api/alerts/config with invalid URL scheme (Should be 400 Bad Request)
	badCfg := newCfg
	badCfg.DiscordWebhookURL = "ftp://evil.com/hook"
	badBytes, _ := json.Marshal(badCfg)
	reqBad := httptest.NewRequest(http.MethodPost, "/api/alerts/config", bytes.NewReader(badBytes))
	reqBad.Header.Set("Content-Type", "application/json")
	reqBad.RemoteAddr = "127.0.0.1:45000"
	recBad := httptest.NewRecorder()
	mux.ServeHTTP(recBad, reqBad)

	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for bad URL scheme, got %d", recBad.Code)
	}
}

func TestAlertEvents_Get(t *testing.T) {
	mux, mockDaemon, cfg := setupAlertTestServer()
	defer mockDaemon.Close()

	// Inject a sample event
	cfg.AlertDispatcher.RecordEvent(alert.Event{
		ID:        "evt_sample_1",
		Level:     alert.LevelWarning,
		Source:    "container:test",
		EventType: "container_exit",
		Message:   "Container test exited",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/alerts/events?limit=10", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	var events []alert.Event
	if err := json.NewDecoder(rec.Body).Decode(&events); err != nil {
		t.Fatalf("failed to decode events slice: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].ID != "evt_sample_1" {
		t.Errorf("expected evt_sample_1, got %s", events[0].ID)
	}
}

func TestAlertTest_Endpoint(t *testing.T) {
	// Setup a mock receiver for webhook
	var webhookReceived bool
	mockWebhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookReceived = true
		w.WriteHeader(http.StatusOK)
	}))
	defer mockWebhook.Close()

	mux, mockDaemon, cfg := setupAlertTestServer()
	defer mockDaemon.Close()

	// Update dispatcher config with mock webhook URL
	_ = cfg.AlertConfigStore.Update(alert.Config{
		Enabled:               false,
		DiscordWebhookURL:     mockWebhook.URL,
		SlackWebhookURL:       "",
		CPUThresholdPercent:   85,
		MemoryThresholdMB:     500,
		RestartThresholdCount: 3,
		FlappingWindowSeconds: 300,
		CooldownSeconds:       60,
	})

	// 1. Successful test dispatch to Discord
	body, _ := json.Marshal(AlertTestRequest{Channel: "discord"})
	req := httptest.NewRequest(http.MethodPost, "/api/alerts/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:50000"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on /api/alerts/test, got %d: %s", rec.Code, rec.Body.String())
	}
	if !webhookReceived {
		t.Errorf("expected mock webhook to receive alert test payload")
	}

	// 2. Test unconfigured channel (slack) returns 400
	bodySlack, _ := json.Marshal(AlertTestRequest{Channel: "slack"})
	reqSlack := httptest.NewRequest(http.MethodPost, "/api/alerts/test", bytes.NewReader(bodySlack))
	reqSlack.Header.Set("Content-Type", "application/json")
	reqSlack.RemoteAddr = "127.0.0.1:50000"
	recSlack := httptest.NewRecorder()
	mux.ServeHTTP(recSlack, reqSlack)

	if recSlack.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 when testing unconfigured slack webhook, got %d", recSlack.Code)
	}

	// 3. Remote address rejected
	reqRemote := httptest.NewRequest(http.MethodPost, "/api/alerts/test", bytes.NewReader(body))
	reqRemote.Header.Set("Content-Type", "application/json")
	reqRemote.RemoteAddr = "8.8.8.8:50000"
	recRemote := httptest.NewRecorder()
	mux.ServeHTTP(recRemote, reqRemote)

	if recRemote.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 on remote address for /api/alerts/test, got %d", recRemote.Code)
	}
}

func TestAlertEndpoint_RateLimiter(t *testing.T) {
	mux := http.NewServeMux()
	limiter := security.NewRateLimiter(1.0, 0.1) // 1 burst, 0.1 refill/sec
	cfgStore := alert.NewConfigStore(alert.DefaultConfig())
	h := &HandlerConfig{
		AlertConfigStore: cfgStore,
		RateLimiter:      limiter,
	}
	mux.HandleFunc("/api/alerts/config", h.handleAlertConfig)

	// First POST consumes the single burst token
	body, _ := json.Marshal(alert.DefaultConfig())
	req1 := httptest.NewRequest(http.MethodPost, "/api/alerts/config", bytes.NewReader(body))
	req1.RemoteAddr = "127.0.0.1:50000"
	rec1 := httptest.NewRecorder()
	mux.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected first request to succeed, got %d", rec1.Code)
	}

	// Second immediate POST must be 429
	req2 := httptest.NewRequest(http.MethodPost, "/api/alerts/config", bytes.NewReader(body))
	req2.RemoteAddr = "127.0.0.1:50000"
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected HTTP 429 on exhausted rate limit, got %d", rec2.Code)
	}
}
