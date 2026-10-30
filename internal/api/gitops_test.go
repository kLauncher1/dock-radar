package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/gitops"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func setupTestGitOpsHandler() (*HandlerConfig, *gitops.Engine) {
	tokenAuth := security.NewTokenAuth("admin-secret-token", "viewer-secret-token", false)
	engine := gitops.NewEngine(gitops.DefaultGitOpsConfig(), nil, nil, nil)

	handler := &HandlerConfig{
		GitOpsEngine: engine,
		TokenAuth:    tokenAuth,
		AllowRemote:  true,
	}
	return handler, engine
}

func TestHandleGitOpsStatus_ViewerAccess(t *testing.T) {
	h, _ := setupTestGitOpsHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/gitops/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	w := httptest.NewRecorder()

	h.handleGitOpsStatus(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got: %d", w.Code)
	}

	var status gitops.GitOpsStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode status: %v", err)
	}
	if !status.Enabled {
		t.Errorf("expected engine enabled")
	}

	// Test unauthenticated access rejected
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/api/gitops/status", nil)
	wNoAuth := httptest.NewRecorder()
	h.handleGitOpsStatus(wNoAuth, reqNoAuth)
	if wNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got: %d", wNoAuth.Code)
	}
}

func TestHandleGitOpsRepos_CRUD(t *testing.T) {
	h, _ := setupTestGitOpsHandler()

	// 1. POST repo with Admin token
	newRepo := gitops.GitRepoConfig{
		ID:              "web-prod",
		Name:            "Production Web",
		RepoURL:         "https://github.com/org/web.git",
		Branch:          "main",
		TargetContainer: "web-prod-container",
		TargetImage:     "web:v1",
		WebhookSecret:   "secret-tok",
	}
	body, _ := json.Marshal(newRepo)
	reqPost := httptest.NewRequest(http.MethodPost, "/api/gitops/repos", bytes.NewReader(body))
	reqPost.Header.Set("Authorization", "Bearer admin-secret-token")
	wPost := httptest.NewRecorder()

	h.handleGitOpsRepos(wPost, reqPost)
	if wPost.Code != http.StatusOK {
		t.Fatalf("expected status 200 on create, got: %d (%s)", wPost.Code, wPost.Body.String())
	}

	// 2. GET repos with Viewer token
	reqGet := httptest.NewRequest(http.MethodGet, "/api/gitops/repos", nil)
	reqGet.Header.Set("Authorization", "Bearer viewer-secret-token")
	wGet := httptest.NewRecorder()

	h.handleGitOpsRepos(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("expected status 200 on list, got: %d", wGet.Code)
	}

	var listResp struct {
		Repositories []gitops.GitRepoConfig `json:"repositories"`
	}
	if err := json.NewDecoder(wGet.Body).Decode(&listResp); err != nil {
		t.Fatalf("failed to decode list: %v", err)
	}
	if len(listResp.Repositories) != 1 {
		t.Errorf("expected 1 repo, got: %d", len(listResp.Repositories))
	}
	if listResp.Repositories[0].WebhookSecret == "secret-tok" {
		t.Errorf("expected secret to be masked in list response")
	}

	// 3. DELETE repo with Admin token
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/gitops/repos?id=web-prod", nil)
	reqDel.Header.Set("Authorization", "Bearer admin-secret-token")
	wDel := httptest.NewRecorder()

	h.handleGitOpsRepos(wDel, reqDel)
	if wDel.Code != http.StatusOK {
		t.Fatalf("expected status 200 on delete, got: %d", wDel.Code)
	}
}

func TestHandleGitOpsDeployAndRollback(t *testing.T) {
	h, engine := setupTestGitOpsHandler()

	_ = engine.AddOrUpdateRepo(gitops.GitRepoConfig{
		ID:              "service-x",
		Name:            "Service X",
		RepoURL:         "https://github.com/org/x.git",
		Branch:          "main",
		TargetContainer: "x-container",
		TargetImage:     "x:v1",
		LastCommitSHA:   "0000000000000000000000000000000000000000",
		AutoRollback:    true,
	})

	// 1. Deploy commit
	deployBody := map[string]string{
		"repo_id":    "service-x",
		"commit_sha": "1111111111111111111111111111111111111111",
	}
	b, _ := json.Marshal(deployBody)
	reqDeploy := httptest.NewRequest(http.MethodPost, "/api/gitops/deploy", bytes.NewReader(b))
	reqDeploy.Header.Set("Authorization", "Bearer admin-secret-token")
	wDeploy := httptest.NewRecorder()

	h.handleGitOpsDeploy(wDeploy, reqDeploy)
	if wDeploy.Code != http.StatusOK {
		t.Fatalf("expected 200 on deploy, got: %d", wDeploy.Code)
	}

	var deployResp struct {
		Status     string                   `json:"status"`
		Deployment *gitops.DeploymentRecord `json:"deployment"`
	}
	if err := json.NewDecoder(wDeploy.Body).Decode(&deployResp); err != nil {
		t.Fatalf("failed to decode deploy response: %v", err)
	}
	if deployResp.Deployment.Status != gitops.DeployStatusSuccess {
		t.Errorf("expected success status, got: %s", deployResp.Deployment.Status)
	}

	// 2. Check deployments list
	reqList := httptest.NewRequest(http.MethodGet, "/api/gitops/deployments", nil)
	reqList.Header.Set("Authorization", "Bearer viewer-secret-token")
	wList := httptest.NewRecorder()

	h.handleGitOpsDeployments(wList, reqList)
	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200 on deployments query, got: %d", wList.Code)
	}

	// 3. Rollback deployment
	rollbackBody := map[string]string{
		"deployment_id": deployResp.Deployment.ID,
		"reason":        "test-rollback-verification",
	}
	rb, _ := json.Marshal(rollbackBody)
	reqRB := httptest.NewRequest(http.MethodPost, "/api/gitops/rollback", bytes.NewReader(rb))
	reqRB.Header.Set("Authorization", "Bearer admin-secret-token")
	wRB := httptest.NewRecorder()

	h.handleGitOpsRollback(wRB, reqRB)
	if wRB.Code != http.StatusOK {
		t.Fatalf("expected 200 on rollback, got: %d (%s)", wRB.Code, wRB.Body.String())
	}
}

func TestHandleGitOpsWebhook_Integration(t *testing.T) {
	h, engine := setupTestGitOpsHandler()

	secret := "secret-webhook-key"
	_ = engine.AddOrUpdateRepo(gitops.GitRepoConfig{
		ID:              "webhook-service",
		Name:            "Webhook Service",
		RepoURL:         "https://github.com/my-org/service.git",
		Branch:          "main",
		TargetContainer: "svc-container",
		TargetImage:     "svc:v1",
		WebhookSecret:   secret,
		LastCommitSHA:   "0000000000000000000000000000000000000000",
	})

	payload := []byte(`{
		"ref": "refs/heads/main",
		"after": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"repository": {
			"clone_url": "https://github.com/my-org/service.git",
			"name": "webhook-service"
		}
	}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sigHex := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/api/gitops/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Hub-Signature-256", sigHex)
	w := httptest.NewRecorder()

	h.handleGitOpsWebhook(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on webhook ingest, got: %d (%s)", w.Code, w.Body.String())
	}
}
