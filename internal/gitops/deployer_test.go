package gitops

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeployer_ExecuteRollout_Success(t *testing.T) {
	// Setup mock healthy endpoint
	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	}))
	defer healthServer.Close()

	deployer := NewDeployer(nil)

	repo := &GitRepoConfig{
		ID:                    "test-service",
		Name:                  "Test Service",
		TargetContainer:       "test-container",
		TargetImage:           "app/test:latest",
		LastCommitSHA:         "1111111111111111111111111111111111111111",
		HealthCheckURL:        healthServer.URL,
		HealthCheckTimeoutSec: 2,
		AutoRollback:          true,
	}

	newSHA := "2222222222222222222222222222222222222222"
	record, err := deployer.ExecuteRollout(context.Background(), repo, newSHA, "webhook")
	if err != nil {
		t.Fatalf("unexpected error during rollout: %v", err)
	}

	if record.Status != DeployStatusSuccess {
		t.Errorf("expected status success, got: %s", record.Status)
	}
	if repo.LastCommitSHA != newSHA {
		t.Errorf("expected updated commit SHA %s, got: %s", newSHA, repo.LastCommitSHA)
	}
}

func TestDeployer_ExecuteRollout_AutoRollbackOnUnhealthy(t *testing.T) {
	// Setup mock failing endpoint (500 Internal Server Error)
	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"status":"fatal error"}`))
	}))
	defer healthServer.Close()

	deployer := NewDeployer(nil)

	originalSHA := "1111111111111111111111111111111111111111"
	repo := &GitRepoConfig{
		ID:                    "test-service-faulty",
		Name:                  "Test Service Faulty",
		TargetContainer:       "test-container",
		TargetImage:           "app/test:latest",
		LastCommitSHA:         originalSHA,
		HealthCheckURL:        healthServer.URL,
		HealthCheckTimeoutSec: 1,
		AutoRollback:          true,
	}

	newSHA := "9999999999999999999999999999999999999999"
	record, err := deployer.ExecuteRollout(context.Background(), repo, newSHA, "webhook")
	if err != nil {
		t.Fatalf("unexpected hard error when auto-rollback is enabled: %v", err)
	}

	if record.Status != DeployStatusRolledBack {
		t.Errorf("expected status rolled_back, got: %s", record.Status)
	}
	if record.RollbackReason == "" {
		t.Errorf("expected non-empty rollback reason")
	}
	// LastCommitSHA should still be original
	if repo.LastCommitSHA != originalSHA {
		t.Errorf("expected repo commit SHA to remain %s after rollback, got %s", originalSHA, repo.LastCommitSHA)
	}
}

func TestDeployer_ExecuteManualRollback(t *testing.T) {
	deployer := NewDeployer(nil)

	originalSHA := "0000000000000000000000000000000000000000"
	currentSHA := "3333333333333333333333333333333333333333"

	repo := &GitRepoConfig{
		ID:            "service-manual",
		LastCommitSHA: currentSHA,
	}

	record := &DeploymentRecord{
		ID:            "deploy-123",
		RepoID:        repo.ID,
		CommitSHA:     currentSHA,
		PrevCommitSHA: originalSHA,
		Status:        DeployStatusSuccess,
	}

	err := deployer.ExecuteManualRollback(context.Background(), repo, record, "operator requested rollback")
	if err != nil {
		t.Fatalf("unexpected error during manual rollback: %v", err)
	}

	if record.Status != DeployStatusRolledBack {
		t.Errorf("expected record status rolled_back, got: %s", record.Status)
	}
	if repo.LastCommitSHA != originalSHA {
		t.Errorf("expected repo to revert to %s, got: %s", originalSHA, repo.LastCommitSHA)
	}
}
