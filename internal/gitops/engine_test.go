package gitops

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestEngine_RepoLifecycle(t *testing.T) {
	engine := NewEngine(DefaultGitOpsConfig(), nil, nil, nil)

	repo := GitRepoConfig{
		ID:              "api-service",
		Name:            "API Service",
		RepoURL:         "https://github.com/my-org/api.git",
		Branch:          "main",
		TargetContainer: "api-container",
		TargetImage:     "api:latest",
		WebhookSecret:   "secret123",
	}

	if err := engine.AddOrUpdateRepo(repo); err != nil {
		t.Fatalf("unexpected error adding repo: %v", err)
	}

	fetched, exists := engine.GetRepo("api-service")
	if !exists {
		t.Fatalf("expected repo to exist")
	}
	if fetched.WebhookSecret == "secret123" {
		t.Errorf("expected masked webhook secret in GetRepo")
	}

	repos := engine.ListRepos()
	if len(repos) != 1 {
		t.Errorf("expected 1 repo, got %d", len(repos))
	}

	if !engine.RemoveRepo("api-service") {
		t.Errorf("expected successful removal")
	}

	if _, exists := engine.GetRepo("api-service"); exists {
		t.Errorf("expected repo to be removed")
	}
}

func TestEngine_DeployAndRollback(t *testing.T) {
	engine := NewEngine(DefaultGitOpsConfig(), nil, nil, nil)

	repo := GitRepoConfig{
		ID:              "backend",
		Name:            "Backend Service",
		RepoURL:         "https://github.com/my-org/backend.git",
		Branch:          "main",
		TargetContainer: "backend-container",
		TargetImage:     "backend:v1",
		LastCommitSHA:   "1111111111111111111111111111111111111111",
		AutoRollback:    true,
	}
	_ = engine.AddOrUpdateRepo(repo)

	// Deploy new commit
	newSHA := "2222222222222222222222222222222222222222"
	record, err := engine.DeployCommit(context.Background(), "backend", newSHA)
	if err != nil {
		t.Fatalf("unexpected error deploying commit: %v", err)
	}
	if record.Status != DeployStatusSuccess {
		t.Errorf("expected deploy status success, got %s", record.Status)
	}

	// Manual Rollback
	err = engine.RollbackDeployment(context.Background(), record.ID, "testing rollback")
	if err != nil {
		t.Fatalf("unexpected error during rollback: %v", err)
	}

	status := engine.Status()
	if status.TotalDeployments != 1 {
		t.Errorf("expected 1 total deployment, got %d", status.TotalDeployments)
	}
	if status.RolledBackDeployments != 1 {
		t.Errorf("expected 1 rolled back deployment, got %d", status.RolledBackDeployments)
	}
}

func TestEngine_HandleWebhook(t *testing.T) {
	engine := NewEngine(DefaultGitOpsConfig(), nil, nil, nil)

	secret := "webhook-token-abc"
	repo := GitRepoConfig{
		ID:              "frontend",
		Name:            "Frontend Web",
		RepoURL:         "https://github.com/my-org/frontend.git",
		Branch:          "main",
		TargetContainer: "frontend-container",
		TargetImage:     "frontend:v1",
		WebhookSecret:   secret,
		LastCommitSHA:   "0000000000000000000000000000000000000000",
	}
	_ = engine.AddOrUpdateRepo(repo)

	payload := []byte(`{
		"ref": "refs/heads/main",
		"after": "5555555555555555555555555555555555555555",
		"repository": {
			"clone_url": "https://github.com/my-org/frontend.git",
			"name": "frontend"
		}
	}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sigHex := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	headers := map[string]string{
		"X-Hub-Signature-256": sigHex,
	}

	record, err := engine.HandleWebhook(context.Background(), payload, headers)
	if err != nil {
		t.Fatalf("unexpected error handling webhook: %v", err)
	}
	if record.Status != DeployStatusSuccess {
		t.Errorf("expected success status, got: %s", record.Status)
	}

	// Test invalid signature
	badHeaders := map[string]string{
		"X-Hub-Signature-256": "sha256=invalidhex",
	}
	_, err = engine.HandleWebhook(context.Background(), payload, badHeaders)
	if err == nil {
		t.Errorf("expected error for invalid signature")
	}

	status := engine.Status()
	if status.SignatureFailuresTotal != 1 {
		t.Errorf("expected 1 signature failure, got %d", status.SignatureFailuresTotal)
	}
}
