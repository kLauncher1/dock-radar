package gitops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
)

// Engine coordinates GitOps continuous repository synchronization, webhook ingestion, and rollouts.
type Engine struct {
	mu                  sync.RWMutex
	config              GitOpsConfig
	repos               map[string]*GitRepoConfig
	deployments         []*DeploymentRecord
	tracker             *RepoTracker
	deployer            *Deployer
	alertDispatcher     *alert.Dispatcher
	auditLogger         *audit.Logger
	totalDeployments    int64
	successDeployments  int64
	rollbackDeployments int64
	failedDeployments   int64
	sigFailuresTotal    int64
	lastSyncTime        time.Time
}

// NewEngine initializes a GitOps continuous delivery engine with tracking, deployment, and audit sinks.
func NewEngine(
	cfg GitOpsConfig,
	dockerClient *docker.Client,
	alertDispatcher *alert.Dispatcher,
	auditLogger *audit.Logger,
) *Engine {
	if cfg.MaxHistory <= 0 {
		cfg.MaxHistory = 100
	}
	return &Engine{
		config:          cfg,
		repos:           make(map[string]*GitRepoConfig),
		deployments:     make([]*DeploymentRecord, 0, cfg.MaxHistory),
		tracker:         NewRepoTracker(nil),
		deployer:        NewDeployer(dockerClient),
		alertDispatcher: alertDispatcher,
		auditLogger:     auditLogger,
	}
}

// SetTracker overrides the repository tracker (useful in unit testing).
func (e *Engine) SetTracker(tracker *RepoTracker) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tracker = tracker
}

// Config returns the global GitOps engine configuration.
func (e *Engine) Config() GitOpsConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

// UpdateConfig modifies global GitOps configuration parameters dynamically.
func (e *Engine) UpdateConfig(newCfg GitOpsConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if newCfg.MaxHistory <= 0 {
		newCfg.MaxHistory = 100
	}
	e.config = newCfg
	return nil
}

// AddOrUpdateRepo registers or modifies a tracked Git repository.
func (e *Engine) AddOrUpdateRepo(repo GitRepoConfig) error {
	if err := ValidateRepoConfig(&repo); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.repos[repo.ID] = &repo

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  "gitops_repo_registered",
			Target:  repo.ID,
			Details: map[string]any{"branch": repo.Branch, "container": repo.TargetContainer},
		})
	}
	return nil
}

// RemoveRepo deletes a tracked repository from the GitOps engine.
func (e *Engine) RemoveRepo(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.repos[id]; !exists {
		return false
	}
	delete(e.repos, id)

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  "gitops_repo_removed",
			Target:  id,
			Details: map[string]any{"id": id},
		})
	}
	return true
}

// GetRepo returns a tracked repository config by ID with secrets masked.
func (e *Engine) GetRepo(id string) (GitRepoConfig, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	r, exists := e.repos[id]
	if !exists {
		return GitRepoConfig{}, false
	}
	return MaskRepoSecret(*r), true
}

// ListRepos returns all registered repositories with masked secrets.
func (e *Engine) ListRepos() []GitRepoConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make([]GitRepoConfig, 0, len(e.repos))
	for _, r := range e.repos {
		out = append(out, MaskRepoSecret(*r))
	}
	return out
}

// SyncRepo performs immediate polling and rollout for a specific tracked repository.
func (e *Engine) SyncRepo(ctx context.Context, repoID string) (*DeploymentRecord, error) {
	e.mu.Lock()
	repo, exists := e.repos[repoID]
	if !exists {
		e.mu.Unlock()
		return nil, fmt.Errorf("repository %q not found", repoID)
	}
	e.mu.Unlock()

	newSHA, hasUpdate, err := e.tracker.CheckUpdate(ctx, repo)
	e.mu.Lock()
	e.lastSyncTime = time.Now().UTC()
	repo.LastSyncTime = e.lastSyncTime
	if err != nil {
		repo.LastSyncStatus = "sync_failed"
		e.mu.Unlock()
		return nil, fmt.Errorf("tracking check failed: %w", err)
	}
	e.mu.Unlock()

	if !hasUpdate {
		return nil, nil // Up to date
	}

	return e.executeDeployment(ctx, repo, newSHA, "poll")
}

// DeployCommit triggers a rollout of a specified commit hash on a repository.
func (e *Engine) DeployCommit(ctx context.Context, repoID string, commitSHA string) (*DeploymentRecord, error) {
	if !IsValidCommitSHA(commitSHA) {
		return nil, errors.New("invalid commit SHA format")
	}

	e.mu.Lock()
	repo, exists := e.repos[repoID]
	if !exists {
		e.mu.Unlock()
		return nil, fmt.Errorf("repository %q not found", repoID)
	}
	e.mu.Unlock()

	return e.executeDeployment(ctx, repo, commitSHA, "manual")
}

// RollbackDeployment reverts a completed deployment back to its previous state.
func (e *Engine) RollbackDeployment(ctx context.Context, deployID string, reason string) error {
	e.mu.Lock()
	var target *DeploymentRecord
	for _, d := range e.deployments {
		if d.ID == deployID {
			target = d
			break
		}
	}
	if target == nil {
		e.mu.Unlock()
		return fmt.Errorf("deployment %q not found", deployID)
	}

	repo, exists := e.repos[target.RepoID]
	if !exists {
		e.mu.Unlock()
		return fmt.Errorf("underlying repository %q no longer exists", target.RepoID)
	}
	e.mu.Unlock()

	if err := e.deployer.ExecuteManualRollback(ctx, repo, target, reason); err != nil {
		return err
	}

	atomic.AddInt64(&e.rollbackDeployments, 1)

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  "gitops_rollback_manual",
			Target:  deployID,
			Details: map[string]any{"repo_id": repo.ID, "commit_sha": target.CommitSHA, "reason": reason},
		})
	}
	return nil
}

// HandleWebhook ingests webhook notifications (GitHub, GitLab, Docker Hub, Gitea), validates signatures, and triggers rollouts.
func (e *Engine) HandleWebhook(ctx context.Context, payload []byte, headers map[string]string) (*DeploymentRecord, error) {
	var body struct {
		Ref        string `json:"ref"`
		After      string `json:"after"`
		Repository struct {
			HTMLURL  string `json:"html_url"`
			CloneURL string `json:"clone_url"`
			FullName string `json:"full_name"`
			Name     string `json:"name"`
		} `json:"repository"`
	}

	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, fmt.Errorf("failed to parse webhook json: %w", err)
	}

	commitSHA := body.After
	if !IsValidCommitSHA(commitSHA) {
		return nil, errors.New("webhook payload missing valid after/commit SHA")
	}

	// Match repository by clone URL, HTML URL, or name
	e.mu.RLock()
	var matchedRepo *GitRepoConfig
	for _, r := range e.repos {
		if strings.EqualFold(r.RepoURL, body.Repository.CloneURL) ||
			strings.EqualFold(r.RepoURL, body.Repository.HTMLURL) ||
			strings.EqualFold(r.ID, body.Repository.Name) ||
			strings.EqualFold(r.Name, body.Repository.Name) {
			matchedRepo = r
			break
		}
	}
	e.mu.RUnlock()

	if matchedRepo == nil {
		return nil, errors.New("no matching tracked repository for webhook event")
	}

	// Signature verification
	secret := matchedRepo.WebhookSecret
	if secret == "" {
		secret = e.config.DefaultWebhookSecret
	}

	if secret != "" {
		ghSig := headers["X-Hub-Signature-256"]
		if ghSig == "" {
			ghSig = headers["x-hub-signature-256"]
		}
		glToken := headers["X-Gitlab-Token"]
		if glToken == "" {
			glToken = headers["x-gitlab-token"]
		}

		valid := false
		if ghSig != "" {
			valid = VerifyWebhookHMAC(payload, secret, ghSig)
		} else if glToken != "" {
			valid = VerifyGitLabToken(glToken, secret)
		}

		if !valid {
			atomic.AddInt64(&e.sigFailuresTotal, 1)
			if e.alertDispatcher != nil {
				_ = e.alertDispatcher.Dispatch(ctx, alert.Event{
					Level:     alert.LevelCritical,
					Source:    "gitops",
					EventType: "webhook_signature_failure",
					Message:   fmt.Sprintf("Invalid cryptographic signature on webhook for repository %s", matchedRepo.ID),
					Timestamp: time.Now().UTC(),
				})
			}
			return nil, errors.New("cryptographic signature verification failed on webhook")
		}
	}

	return e.executeDeployment(ctx, matchedRepo, commitSHA, "webhook")
}

func (e *Engine) executeDeployment(ctx context.Context, repo *GitRepoConfig, sha string, trigger string) (*DeploymentRecord, error) {
	atomic.AddInt64(&e.totalDeployments, 1)

	record, err := e.deployer.ExecuteRollout(ctx, repo, sha, trigger)

	e.mu.Lock()
	if record != nil {
		e.deployments = append(e.deployments, record)
		if len(e.deployments) > e.config.MaxHistory {
			e.deployments = e.deployments[len(e.deployments)-e.config.MaxHistory:]
		}
	}
	e.mu.Unlock()

	if record != nil {
		switch record.Status {
		case DeployStatusSuccess:
			atomic.AddInt64(&e.successDeployments, 1)
			if e.alertDispatcher != nil {
				_ = e.alertDispatcher.Dispatch(ctx, alert.Event{
					Level:     alert.LevelInfo,
					Source:    "gitops",
					EventType: "deployment_success",
					Message:   fmt.Sprintf("Repository %s successfully deployed commit %s to container %s", repo.ID, sha[:min(8, len(sha))], repo.TargetContainer),
					Timestamp: time.Now().UTC(),
				})
			}
		case DeployStatusRolledBack:
			atomic.AddInt64(&e.rollbackDeployments, 1)
			if e.alertDispatcher != nil {
				_ = e.alertDispatcher.Dispatch(ctx, alert.Event{
					Level:     alert.LevelWarning,
					Source:    "gitops",
					EventType: "deployment_rollback",
					Message:   fmt.Sprintf("Repository %s rollout failed health gating; automatically reverted to commit %s (%s)", repo.ID, record.PrevCommitSHA, record.RollbackReason),
					Timestamp: time.Now().UTC(),
				})
			}
		case DeployStatusFailed:
			atomic.AddInt64(&e.failedDeployments, 1)
		}
	}

	if e.auditLogger != nil && record != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  "gitops_deploy_" + string(record.Status),
			Target:  record.ID,
			Details: map[string]any{"repo_id": repo.ID, "commit_sha": sha, "trigger": trigger},
		})
	}

	return record, err
}

// ListDeployments returns the most recent deployment records up to limit.
func (e *Engine) ListDeployments(limit int) []*DeploymentRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()

	n := len(e.deployments)
	if limit <= 0 || limit > n {
		limit = n
	}

	out := make([]*DeploymentRecord, limit)
	for i := 0; i < limit; i++ {
		out[i] = e.deployments[n-1-i]
	}
	return out
}

// Status returns aggregate metrics for Prometheus exporters and management dashboards.
func (e *Engine) Status() GitOpsStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return GitOpsStatus{
		Enabled:                e.config.Enabled,
		TrackedReposCount:      len(e.repos),
		TotalDeployments:       atomic.LoadInt64(&e.totalDeployments),
		SuccessfulDeployments:  atomic.LoadInt64(&e.successDeployments),
		RolledBackDeployments:  atomic.LoadInt64(&e.rollbackDeployments),
		FailedDeployments:      atomic.LoadInt64(&e.failedDeployments),
		SignatureFailuresTotal: atomic.LoadInt64(&e.sigFailuresTotal),
		LastSyncTime:           e.lastSyncTime,
	}
}

// Start launches the background periodic polling loop for all enabled repositories.
func (e *Engine) Start(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.mu.RLock()
			enabled := e.config.Enabled
			repoList := make([]*GitRepoConfig, 0, len(e.repos))
			for _, r := range e.repos {
				if r.Enabled {
					repoList = append(repoList, r)
				}
			}
			e.mu.RUnlock()

			if !enabled {
				continue
			}

			for _, repo := range repoList {
				interval := repo.PollIntervalSec
				if interval <= 0 {
					interval = 30
				}
				if time.Since(repo.LastSyncTime) >= time.Duration(interval)*time.Second {
					_, _ = e.SyncRepo(ctx, repo.ID)
				}
			}
		}
	}
}
