package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/canary"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupCanaryTestHandler() (*HandlerConfig, *canary.Engine) {
	auditLogger := audit.NewLogger(100)
	engine := canary.NewEngine(canary.DefaultCanaryConfig(), auditLogger, nil)
	tokenAuth := security.NewTokenAuth("admin-secret-token", "viewer-secret-token", false)

	cfg := &HandlerConfig{
		CanaryEngine: engine,
		TokenAuth:    tokenAuth,
	}
	return cfg, engine
}

func TestHandleCanaryStatus_ViewerAccess(t *testing.T) {
	cfg, _ := setupCanaryTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/canary/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w := httptest.NewRecorder()

	cfg.handleCanaryStatus(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var status canary.CanaryStatus
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to decode status: %v", err)
	}
	if !status.Enabled {
		t.Fatalf("expected canary engine to be enabled")
	}
}

func TestHandleCanaryDeployments_CRUDAndRBAC(t *testing.T) {
	cfg, engine := setupCanaryTestHandler()

	// 1. Unauthorized create attempt (Viewer token on POST)
	payload := canary.CanaryDeployment{
		ID:                  "test-api-canary",
		Name:                "Test API Canary",
		ServiceName:         "auth-svc",
		BaselineContainerID: "cont-base",
		CanaryContainerID:   "cont-canary",
		Traffic: canary.TrafficSplitConfig{
			BaselineWeight: 80,
			CanaryWeight:   20,
		},
		Rollback: canary.RollbackPolicy{
			AutoRollback:          true,
			MaxErrorRateDelta:     5.0,
			MaxLatencyP95Ratio:    1.5,
			MinSampleSize:         20,
			ConsecutiveViolations: 1,
		},
	}
	body, _ := json.Marshal(payload)

	reqViewer := httptest.NewRequest(http.MethodPost, "/api/canary/deployments", bytes.NewReader(body))
	reqViewer.Header.Set("Authorization", "Bearer viewer-secret-token")
	wViewer := httptest.NewRecorder()
	cfg.handleCanaryDeployments(wViewer, reqViewer)
	if wViewer.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer on POST, got %d", wViewer.Code)
	}

	// 2. Authorized create (Admin token)
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/canary/deployments", bytes.NewReader(body))
	reqAdmin.Header.Set("Authorization", "Bearer admin-secret-token")
	wAdmin := httptest.NewRecorder()
	cfg.handleCanaryDeployments(wAdmin, reqAdmin)
	if wAdmin.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for admin on POST, got %d: %s", wAdmin.Code, wAdmin.Body.String())
	}

	// 3. List deployments (Viewer token)
	reqList := httptest.NewRequest(http.MethodGet, "/api/canary/deployments", nil)
	reqList.Header.Set("Authorization", "Bearer viewer-secret-token")
	wList := httptest.NewRecorder()
	cfg.handleCanaryDeployments(wList, reqList)
	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on list, got %d", wList.Code)
	}
	var list []*canary.CanaryDeployment
	_ = json.Unmarshal(wList.Body.Bytes(), &list)
	if len(list) != 1 || list[0].ID != "test-api-canary" {
		t.Fatalf("expected 1 deployment test-api-canary, got %v", list)
	}

	// 4. Detail view
	reqDetail := httptest.NewRequest(http.MethodGet, "/api/canary/deployments/detail?id=test-api-canary", nil)
	reqDetail.Header.Set("Authorization", "Bearer viewer-secret-token")
	wDetail := httptest.NewRecorder()
	cfg.handleCanaryDeploymentDetail(wDetail, reqDetail)
	if wDetail.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on detail, got %d", wDetail.Code)
	}

	// 5. Weight adjustment
	weightReq := canaryWeightRequest{ID: "test-api-canary", CanaryWeight: 40}
	wBody, _ := json.Marshal(weightReq)
	reqWeight := httptest.NewRequest(http.MethodPost, "/api/canary/deployments/weight", bytes.NewReader(wBody))
	reqWeight.Header.Set("Authorization", "Bearer admin-secret-token")
	wWeight := httptest.NewRecorder()
	cfg.handleCanaryWeight(wWeight, reqWeight)
	if wWeight.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on weight update, got %d: %s", wWeight.Code, wWeight.Body.String())
	}

	// 6. Route traffic simulation
	routeReq := canaryRouteRequest{ID: "test-api-canary", RequestID: "req-sim-1"}
	rBody, _ := json.Marshal(routeReq)
	reqRoute := httptest.NewRequest(http.MethodPost, "/api/canary/deployments/route", bytes.NewReader(rBody))
	reqRoute.Header.Set("Authorization", "Bearer viewer-secret-token")
	wRoute := httptest.NewRecorder()
	cfg.handleCanaryRoute(wRoute, reqRoute)
	if wRoute.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on route traffic, got %d", wRoute.Code)
	}

	// 7. Record sample
	sampleReq := canarySampleRequest{ID: "test-api-canary", Target: "canary", StatusCode: 200, DurationMs: 14.5}
	sBody, _ := json.Marshal(sampleReq)
	reqSample := httptest.NewRequest(http.MethodPost, "/api/canary/deployments/sample", bytes.NewReader(sBody))
	reqSample.Header.Set("Authorization", "Bearer admin-secret-token")
	wSample := httptest.NewRecorder()
	cfg.handleCanarySample(wSample, reqSample)
	if wSample.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on sample record, got %d", wSample.Code)
	}

	// 8. Promote
	actionReq := canaryActionRequest{ID: "test-api-canary"}
	aBody, _ := json.Marshal(actionReq)
	reqPromote := httptest.NewRequest(http.MethodPost, "/api/canary/deployments/promote", bytes.NewReader(aBody))
	reqPromote.Header.Set("Authorization", "Bearer admin-secret-token")
	wPromote := httptest.NewRecorder()
	cfg.handleCanaryPromote(wPromote, reqPromote)
	if wPromote.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on promote, got %d", wPromote.Code)
	}

	// 9. Rollback
	rollbackReq := canaryActionRequest{ID: "test-api-canary", Reason: "drill"}
	rbBody, _ := json.Marshal(rollbackReq)
	reqRollback := httptest.NewRequest(http.MethodPost, "/api/canary/deployments/rollback", bytes.NewReader(rbBody))
	reqRollback.Header.Set("Authorization", "Bearer admin-secret-token")
	wRollback := httptest.NewRecorder()
	cfg.handleCanaryRollback(wRollback, reqRollback)
	if wRollback.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on rollback, got %d", wRollback.Code)
	}

	// 10. Delete deployment
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/canary/deployments/detail?id=test-api-canary", nil)
	reqDel.Header.Set("Authorization", "Bearer admin-secret-token")
	wDel := httptest.NewRecorder()
	cfg.handleCanaryDeploymentDetail(wDel, reqDel)
	if wDel.Code != http.StatusNoContent {
		t.Fatalf("expected 204 NoContent on delete, got %d", wDel.Code)
	}

	// Verify gone from engine
	_, err := engine.GetDeployment("test-api-canary")
	if err != canary.ErrDeploymentNotFound {
		t.Fatalf("expected ErrDeploymentNotFound, got %v", err)
	}
}

func TestHandleCanaryConfig_GetAndPost(t *testing.T) {
	cfg, _ := setupCanaryTestHandler()

	// GET config
	reqGet := httptest.NewRequest(http.MethodGet, "/api/canary/config", nil)
	reqGet.Header.Set("Authorization", "Bearer viewer-secret-token")
	wGet := httptest.NewRecorder()
	cfg.handleCanaryConfig(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on get config, got %d", wGet.Code)
	}

	// POST update config
	updated := canary.CanaryConfig{
		Enabled:             true,
		DefaultAutoRollback: true,
		DefaultShadowMirror: false,
		MaxDeployments:      64,
	}
	body, _ := json.Marshal(updated)
	reqPost := httptest.NewRequest(http.MethodPost, "/api/canary/config", bytes.NewReader(body))
	reqPost.Header.Set("Authorization", "Bearer admin-secret-token")
	wPost := httptest.NewRecorder()
	cfg.handleCanaryConfig(wPost, reqPost)
	if wPost.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on post config, got %d", wPost.Code)
	}
}
