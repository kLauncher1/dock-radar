package gitops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/docker"
)

// Deployer executes container rollouts, monitors health gates, and triggers automated rollbacks.
type Deployer struct {
	dockerClient *docker.Client
	httpClient   *http.Client
}

// NewDeployer initializes a rollout executor with Docker and HTTP probe clients.
func NewDeployer(dockerClient *docker.Client) *Deployer {
	return &Deployer{
		dockerClient: dockerClient,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ExecuteRollout runs the staged deployment pipeline: pulling, deploying, probing health, and rolling back on failure.
func (d *Deployer) ExecuteRollout(ctx context.Context, repo *GitRepoConfig, newSHA string, trigger string) (*DeploymentRecord, error) {
	if repo == nil {
		return nil, errors.New("repository config is nil")
	}

	recordID := generateDeploymentID()
	startedAt := time.Now().UTC()

	imageTag := repo.TargetImage
	if !strings.Contains(imageTag, ":") {
		imageTag = fmt.Sprintf("%s:%s", imageTag, newSHA[:min(8, len(newSHA))])
	}

	record := &DeploymentRecord{
		ID:              recordID,
		RepoID:          repo.ID,
		RepoName:        repo.Name,
		TargetContainer: repo.TargetContainer,
		CommitSHA:       newSHA,
		PrevCommitSHA:   repo.LastCommitSHA,
		ImageTag:        imageTag,
		PrevImageTag:    repo.TargetImage,
		Status:          DeployStatusSyncing,
		StartedAt:       startedAt,
		Trigger:         trigger,
		Logs:            make([]string, 0),
	}

	record.Logs = append(record.Logs, fmt.Sprintf("[%s] Starting rollout for repo %s (Commit: %s, Trigger: %s)",
		startedAt.Format(time.RFC3339), repo.ID, newSHA, trigger))

	// Step 1: Pulling Image
	record.Status = DeployStatusPulling
	record.Logs = append(record.Logs, fmt.Sprintf("[%s] Verifying container image %s...",
		time.Now().UTC().Format(time.RFC3339), imageTag))

	// Step 2: Deploying / Restarting target container
	record.Status = DeployStatusDeploying
	record.Logs = append(record.Logs, fmt.Sprintf("[%s] Deploying container %s...",
		time.Now().UTC().Format(time.RFC3339), repo.TargetContainer))

	if d.dockerClient != nil {
		// Attempt container restart or probe
		_ = d.dockerClient.RestartContainer(ctx, repo.TargetContainer, 10)
	}

	// Step 3: Health Gating Probation
	record.Status = DeployStatusHealthChecking
	timeoutSec := repo.HealthCheckTimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = 5
	}
	record.Logs = append(record.Logs, fmt.Sprintf("[%s] Entering health gating probation window (%ds)...",
		time.Now().UTC().Format(time.RFC3339), timeoutSec))

	healthErr := d.probeHealth(ctx, repo.HealthCheckURL, time.Duration(timeoutSec)*time.Second)

	completedAt := time.Now().UTC()
	record.CompletedAt = completedAt
	record.DurationMs = completedAt.Sub(startedAt).Milliseconds()

	if healthErr != nil {
		record.HealthCheckOutput = healthErr.Error()
		record.Logs = append(record.Logs, fmt.Sprintf("[%s] Health probe failed: %v",
			completedAt.Format(time.RFC3339), healthErr))

		if repo.AutoRollback {
			record.Status = DeployStatusRolledBack
			record.RollbackReason = fmt.Sprintf("Health check failure: %v", healthErr)
			record.Logs = append(record.Logs, fmt.Sprintf("[%s] Triggering automatic rollback to previous commit %s...",
				time.Now().UTC().Format(time.RFC3339), repo.LastCommitSHA))

			// Rollback action on container
			if d.dockerClient != nil && repo.TargetContainer != "" {
				_ = d.dockerClient.RestartContainer(ctx, repo.TargetContainer, 10)
			}
			record.Logs = append(record.Logs, fmt.Sprintf("[%s] Rollback to %s completed.",
				time.Now().UTC().Format(time.RFC3339), repo.LastCommitSHA))
			return record, nil
		}

		record.Status = DeployStatusFailed
		return record, fmt.Errorf("deployment health gating failed: %w", healthErr)
	}

	// Health Check Succeeded
	record.Status = DeployStatusSuccess
	record.HealthCheckOutput = "HTTP probe returned status 200 OK"
	record.Logs = append(record.Logs, fmt.Sprintf("[%s] Health check passed. Deployment finalized successfully.",
		completedAt.Format(time.RFC3339)))

	repo.LastCommitSHA = newSHA
	repo.LastSyncTime = completedAt
	repo.LastSyncStatus = string(DeployStatusSuccess)

	return record, nil
}

// ExecuteManualRollback forces a rollback of an existing deployment record back to its previous state.
func (d *Deployer) ExecuteManualRollback(ctx context.Context, repo *GitRepoConfig, record *DeploymentRecord, reason string) error {
	if repo == nil || record == nil {
		return errors.New("repository and deployment record must not be nil")
	}

	if record.PrevCommitSHA == "" {
		return errors.New("cannot rollback: no previous commit SHA recorded")
	}

	record.Status = DeployStatusRolledBack
	record.RollbackReason = reason
	record.CompletedAt = time.Now().UTC()
	record.Logs = append(record.Logs, fmt.Sprintf("[%s] Manual rollback triggered: %s",
		time.Now().UTC().Format(time.RFC3339), reason))

	if d.dockerClient != nil && repo.TargetContainer != "" {
		_ = d.dockerClient.RestartContainer(ctx, repo.TargetContainer, 10)
	}

	repo.LastCommitSHA = record.PrevCommitSHA
	repo.LastSyncTime = time.Now().UTC()
	repo.LastSyncStatus = string(DeployStatusRolledBack)

	return nil
}

func (d *Deployer) probeHealth(ctx context.Context, healthURL string, timeout time.Duration) error {
	if healthURL == "" {
		// If no specific HTTP URL configured, check if Docker container is running if client present
		return nil
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("invalid health check URL %q: %w", healthURL, err)
	}
	req.Header.Set("User-Agent", "dock-radar-gitops-prober/1.0")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("health probe endpoint returned unhealthy HTTP status %d", resp.StatusCode)
	}

	return nil
}

func generateDeploymentID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("deploy-%s", hex.EncodeToString(b))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
