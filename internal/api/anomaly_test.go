package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/anomaly"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestAnomalyAPI() (*HandlerConfig, *http.ServeMux) {
	mux := http.NewServeMux()
	tokenAuth := security.NewTokenAuth("admin-secret", "viewer-secret", false)
	cfg := RegisterRoutesWithSecurity(mux, docker.NewClient(), nil, tokenAuth, false)

	detector := anomaly.NewDetector(nil, nil)
	cfg.AnomalyDetector = detector
	cfg.AuditLogger = audit.NewLogger(100)

	// Seed some test data into detector store
	now := time.Now().UTC()
	detector.Store().RecordMetric("c-leaky", "leaky-service", anomaly.MetricSample{
		Timestamp:   now.Add(-4 * time.Second),
		MemoryBytes: 90000000,
		MemoryLimit: 100000000,
	})
	detector.Store().RecordMetric("c-leaky", "leaky-service", anomaly.MetricSample{
		Timestamp:   now.Add(-2 * time.Second),
		MemoryBytes: 94000000,
		MemoryLimit: 100000000,
	})
	detector.Store().RecordMetric("c-leaky", "leaky-service", anomaly.MetricSample{
		Timestamp:   now,
		MemoryBytes: 98000000,
		MemoryLimit: 100000000,
	})

	// Sample once to populate predictions & alarms
	_, _ = detector.SampleOnce(context.Background())

	// Manually trigger an event into alarms
	pred := anomaly.PredictExhaustion("c-leaky", "leaky-service", detector.Store().AllSeries()["c-leaky"].Samples(), 100000000)
	detector.Alarms().EvaluateAndDispatch(pred, nil)

	return cfg, mux
}

func TestHandleAnomalyPredictions_ViewerAccess(t *testing.T) {
	_, mux := setupTestAnomalyAPI()

	req := httptest.NewRequest(http.MethodGet, "/api/anomaly/predictions", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp AnomalyPredictionsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode predictions response: %v", err)
	}

	if len(resp.Predictions) != 1 {
		t.Fatalf("expected 1 prediction, got %d", len(resp.Predictions))
	}
	if resp.Predictions[0].ContainerID != "c-leaky" {
		t.Fatalf("expected container ID 'c-leaky', got '%s'", resp.Predictions[0].ContainerID)
	}
}

func TestHandleAnomalyPredictions_Filter(t *testing.T) {
	_, mux := setupTestAnomalyAPI()

	// Filter by at_risk
	req := httptest.NewRequest(http.MethodGet, "/api/anomaly/predictions?filter=at_risk", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}

	var resp AnomalyPredictionsResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Predictions) != 1 {
		t.Fatalf("expected 1 at_risk prediction, got %d", len(resp.Predictions))
	}

	// Filter by non-existent ID
	req2 := httptest.NewRequest(http.MethodGet, "/api/anomaly/predictions?id=nonexistent", nil)
	req2.Header.Set("Authorization", "Bearer viewer-secret")
	rr2 := httptest.NewRecorder()

	mux.ServeHTTP(rr2, req2)
	var resp2 AnomalyPredictionsResponse
	_ = json.NewDecoder(rr2.Body).Decode(&resp2)
	if len(resp2.Predictions) != 0 {
		t.Fatalf("expected 0 predictions for nonexistent ID, got %d", len(resp2.Predictions))
	}
}

func TestHandleAnomalyConfig_RBAC(t *testing.T) {
	_, mux := setupTestAnomalyAPI()

	// GET with viewer token should succeed
	getReq := httptest.NewRequest(http.MethodGet, "/api/anomaly/config", nil)
	getReq.Header.Set("Authorization", "Bearer viewer-secret")
	getRR := httptest.NewRecorder()
	mux.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for viewer GET config, got %d", getRR.Code)
	}

	// POST with viewer token should be forbidden (requires admin)
	updatePayload, _ := json.Marshal(anomaly.AlarmConfig{
		Enabled:                true,
		WarningHorizonSeconds:  600,
		CriticalHorizonSeconds: 120,
	})
	postViewerReq := httptest.NewRequest(http.MethodPost, "/api/anomaly/config", bytes.NewReader(updatePayload))
	postViewerReq.Header.Set("Authorization", "Bearer viewer-secret")
	postViewerRR := httptest.NewRecorder()
	mux.ServeHTTP(postViewerRR, postViewerReq)
	if postViewerRR.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for viewer POST, got %d", postViewerRR.Code)
	}

	// POST with admin token should succeed
	postAdminReq := httptest.NewRequest(http.MethodPost, "/api/anomaly/config", bytes.NewReader(updatePayload))
	postAdminReq.Header.Set("Authorization", "Bearer admin-secret")
	postAdminRR := httptest.NewRecorder()
	mux.ServeHTTP(postAdminRR, postAdminReq)
	if postAdminRR.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for admin POST, got %d: %s", postAdminRR.Code, postAdminRR.Body.String())
	}

	var updated anomaly.AlarmConfig
	_ = json.NewDecoder(postAdminRR.Body).Decode(&updated)
	if updated.WarningHorizonSeconds != 600 {
		t.Fatalf("expected updated warning horizon 600, got %d", updated.WarningHorizonSeconds)
	}
}

func TestHandleAnomalyEvents_Get(t *testing.T) {
	_, mux := setupTestAnomalyAPI()

	req := httptest.NewRequest(http.MethodGet, "/api/anomaly/events?limit=10", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}

	var resp AnomalyEventsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode events response: %v", err)
	}

	if len(resp.Events) == 0 {
		t.Fatalf("expected at least 1 alarm event, got 0")
	}
	if resp.Events[0].ContainerID != "c-leaky" {
		t.Fatalf("expected container ID 'c-leaky', got '%s'", resp.Events[0].ContainerID)
	}
}
