package gitops

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// SignaturePolicy defines cryptographic signature enforcement levels for commits and webhooks.
type SignaturePolicy string

const (
	PolicyDisabled SignaturePolicy = "disabled"
	PolicyWarn     SignaturePolicy = "warn"
	PolicyStrict   SignaturePolicy = "strict"
)

// SignatureStatus indicates verification results of a commit's cryptographic signature.
type SignatureStatus string

const (
	SigStatusUnsigned  SignatureStatus = "unsigned"
	SigStatusValid     SignatureStatus = "valid"
	SigStatusInvalid   SignatureStatus = "invalid"
	SigStatusUntrusted SignatureStatus = "untrusted"
)

// DeploymentStatus indicates the lifecycle phase of a GitOps rollout operation.
type DeploymentStatus string

const (
	DeployStatusPending        DeploymentStatus = "pending"
	DeployStatusSyncing        DeploymentStatus = "syncing"
	DeployStatusPulling        DeploymentStatus = "pulling"
	DeployStatusDeploying      DeploymentStatus = "deploying"
	DeployStatusHealthChecking DeploymentStatus = "health_checking"
	DeployStatusSuccess        DeploymentStatus = "success"
	DeployStatusRolledBack     DeploymentStatus = "rolled_back"
	DeployStatusFailed         DeploymentStatus = "failed"
)

// GitRepoConfig represents configuration for a continuously tracked git repository.
type GitRepoConfig struct {
	ID                    string          `json:"id"`
	Name                  string          `json:"name"`
	RepoURL               string          `json:"repo_url"`
	Branch                string          `json:"branch"`
	TargetContainer       string          `json:"target_container"`
	TargetImage           string          `json:"target_image"`
	WebhookSecret         string          `json:"webhook_secret,omitempty"`
	SignaturePolicy       SignaturePolicy `json:"signature_policy"`
	AuthorizedSigners     []string        `json:"authorized_signers,omitempty"`
	HealthCheckURL        string          `json:"health_check_url,omitempty"`
	HealthCheckTimeoutSec int             `json:"health_check_timeout_sec"`
	AutoRollback          bool            `json:"auto_rollback"`
	PollIntervalSec       int             `json:"poll_interval_sec"`
	Enabled               bool            `json:"enabled"`
	LastCommitSHA         string          `json:"last_commit_sha,omitempty"`
	LastSyncTime          time.Time       `json:"last_sync_time,omitempty"`
	LastSyncStatus        string          `json:"last_sync_status,omitempty"`
}

// CommitInfo holds parsed metadata and signature status for a Git commit.
type CommitInfo struct {
	Hash            string          `json:"hash"`
	ShortHash       string          `json:"short_hash"`
	Author          string          `json:"author"`
	Email           string          `json:"email"`
	Message         string          `json:"message"`
	Timestamp       time.Time       `json:"timestamp"`
	Signature       string          `json:"signature,omitempty"`
	SignatureKeyID  string          `json:"signature_key_id,omitempty"`
	SignatureStatus SignatureStatus `json:"signature_status"`
}

// DeploymentRecord documents an automated or triggered rollout execution.
type DeploymentRecord struct {
	ID                string           `json:"id"`
	RepoID            string           `json:"repo_id"`
	RepoName          string           `json:"repo_name"`
	TargetContainer   string           `json:"target_container"`
	CommitSHA         string           `json:"commit_sha"`
	PrevCommitSHA     string           `json:"prev_commit_sha"`
	ImageTag          string           `json:"image_tag"`
	PrevImageTag      string           `json:"prev_image_tag"`
	Status            DeploymentStatus `json:"status"`
	StartedAt         time.Time        `json:"started_at"`
	CompletedAt       time.Time        `json:"completed_at,omitempty"`
	DurationMs        int64            `json:"duration_ms"`
	Trigger           string           `json:"trigger"` // "webhook", "poll", "manual"
	RollbackReason    string           `json:"rollback_reason,omitempty"`
	HealthCheckOutput string           `json:"health_check_output,omitempty"`
	Logs              []string         `json:"logs,omitempty"`
}

// GitOpsConfig controls global behavior of the GitOps synchronization subsystem.
type GitOpsConfig struct {
	Enabled               bool            `json:"enabled"`
	DefaultPollIntervalSec int            `json:"default_poll_interval_sec"`
	DefaultSignaturePolicy SignaturePolicy `json:"default_signature_policy"`
	AutoRollback          bool            `json:"auto_rollback"`
	DefaultWebhookSecret  string          `json:"default_webhook_secret,omitempty"`
	MaxHistory            int             `json:"max_history"`
}

// GitOpsStatus reflects aggregate operational metrics for the GitOps continuous delivery engine.
type GitOpsStatus struct {
	Enabled                    bool      `json:"enabled"`
	TrackedReposCount          int       `json:"tracked_repos_count"`
	TotalDeployments           int64     `json:"total_deployments"`
	SuccessfulDeployments      int64     `json:"successful_deployments"`
	RolledBackDeployments      int64     `json:"rolled_back_deployments"`
	FailedDeployments          int64     `json:"failed_deployments"`
	SignatureFailuresTotal     int64     `json:"signature_failures_total"`
	LastSyncTime               time.Time `json:"last_sync_time,omitempty"`
	ActiveDeploymentsCount     int       `json:"active_deployments_count"`
}

var (
	validIDRegex     = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{2,64}$`)
	validSHA1Regex   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	validSHA256Regex = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

// DefaultGitOpsConfig returns safe production defaults for the GitOps engine.
func DefaultGitOpsConfig() GitOpsConfig {
	return GitOpsConfig{
		Enabled:                true,
		DefaultPollIntervalSec: 30,
		DefaultSignaturePolicy: PolicyWarn,
		AutoRollback:           true,
		DefaultWebhookSecret:   "",
		MaxHistory:             100,
	}
}

// ValidateRepoConfig validates sanity bounds and formats of a repository definition.
func ValidateRepoConfig(cfg *GitRepoConfig) error {
	if cfg == nil {
		return errors.New("repository config is nil")
	}
	cfg.ID = strings.TrimSpace(cfg.ID)
	if !validIDRegex.MatchString(cfg.ID) {
		return errors.New("repository id must be 2-64 alphanumeric characters (hyphens, dots, underscores allowed)")
	}
	cfg.RepoURL = strings.TrimSpace(cfg.RepoURL)
	if err := ValidateRepoURL(cfg.RepoURL); err != nil {
		return err
	}
	cfg.Branch = strings.TrimSpace(cfg.Branch)
	if cfg.Branch == "" {
		cfg.Branch = "main"
	}
	cfg.TargetContainer = strings.TrimSpace(cfg.TargetContainer)
	if cfg.TargetContainer == "" {
		return errors.New("target container name or id is required")
	}
	cfg.TargetImage = strings.TrimSpace(cfg.TargetImage)
	if cfg.TargetImage == "" {
		return errors.New("target image is required")
	}
	if cfg.SignaturePolicy == "" {
		cfg.SignaturePolicy = PolicyWarn
	}
	switch cfg.SignaturePolicy {
	case PolicyDisabled, PolicyWarn, PolicyStrict:
	default:
		return errors.New("invalid signature policy: must be disabled, warn, or strict")
	}
	if cfg.PollIntervalSec <= 0 {
		cfg.PollIntervalSec = 30
	}
	if cfg.HealthCheckTimeoutSec <= 0 {
		cfg.HealthCheckTimeoutSec = 10
	}
	return nil
}

// ValidateRepoURL ensures the Git repository URL follows legitimate HTTP/HTTPS or SSH transport syntax.
func ValidateRepoURL(repoURL string) error {
	if repoURL == "" {
		return errors.New("repository URL cannot be empty")
	}
	// Support SSH URLs like git@github.com:org/repo.git
	if strings.HasPrefix(repoURL, "git@") {
		parts := strings.SplitN(repoURL, ":", 2)
		if len(parts) != 2 || parts[1] == "" {
			return errors.New("malformed git SSH URL")
		}
		return nil
	}
	parsed, err := url.Parse(repoURL)
	if err != nil {
		return errors.New("invalid repository URL syntax")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "git" {
		return errors.New("repository URL scheme must be http, https, git, or git@ ssh")
	}
	if parsed.Host == "" {
		return errors.New("repository URL host is missing")
	}
	return nil
}

// MaskRepoSecret returns a copy of the repository configuration with sensitive secrets obfuscated.
func MaskRepoSecret(r GitRepoConfig) GitRepoConfig {
	cp := r
	if cp.WebhookSecret != "" {
		if len(cp.WebhookSecret) > 4 {
			cp.WebhookSecret = cp.WebhookSecret[:2] + "****" + cp.WebhookSecret[len(cp.WebhookSecret)-2:]
		} else {
			cp.WebhookSecret = "****"
		}
	}
	return cp
}

// IsValidCommitSHA checks whether a string is a 40-character SHA-1 or 64-character SHA-256 hash.
func IsValidCommitSHA(sha string) bool {
	return validSHA1Regex.MatchString(sha) || validSHA256Regex.MatchString(sha)
}
