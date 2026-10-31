package canary

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ErrDeploymentNotFound   = errors.New("canary deployment not found")
	ErrDeploymentExists     = errors.New("canary deployment already exists")
	ErrInvalidDeploymentID  = errors.New("invalid canary deployment id")
	ErrInvalidContainerID   = errors.New("invalid container id")
	ErrInvalidWeight        = errors.New("traffic weight must be between 0 and 100")
	ErrInvalidSampleRate    = errors.New("shadow mirror sample rate must be between 0.0 and 1.0")
	ErrInvalidThreshold     = errors.New("threshold value must be positive")
	ErrDeploymentInactive   = errors.New("canary deployment is not active")
)

var validIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{1,64}$`)

// CanaryPhase defines the lifecycle phase of a canary rollout.
type CanaryPhase string

const (
	PhasePending    CanaryPhase = "pending"
	PhaseActive     CanaryPhase = "active"
	PhaseEvaluating CanaryPhase = "evaluating"
	PhasePromoting  CanaryPhase = "promoting"
	PhaseRolledBack CanaryPhase = "rolled_back"
	PhaseCompleted  CanaryPhase = "completed"
	PhaseFailed     CanaryPhase = "failed"
)

// TrafficSplitConfig defines dynamic traffic weight distribution between versions.
type TrafficSplitConfig struct {
	BaselineWeight       int    `json:"baseline_weight"`
	CanaryWeight         int    `json:"canary_weight"`
	HeaderAffinity       string `json:"header_affinity,omitempty"`
	CanaryHeaderOverride string `json:"canary_header_override,omitempty"`
}

// ShadowMirrorConfig defines asynchronous shadow traffic mirroring parameters.
type ShadowMirrorConfig struct {
	Enabled           bool    `json:"enabled"`
	SampleRate        float64 `json:"sample_rate"` // 0.0 to 1.0
	MaxQueueSize      int     `json:"max_queue_size"`
	WorkerConcurrency int     `json:"worker_concurrency"`
	TimeoutMs         int     `json:"timeout_ms"`
}

// RollbackPolicy defines automated rollback conditions based on divergence.
type RollbackPolicy struct {
	AutoRollback          bool    `json:"auto_rollback"`
	MaxErrorRateDelta     float64 `json:"max_error_rate_delta"`   // Percentage points (e.g. 5.0%)
	MaxLatencyP95Ratio    float64 `json:"max_latency_p95_ratio"`  // e.g. 1.5x baseline p95
	MinSampleSize         int     `json:"min_sample_size"`         // Minimum samples before tripping
	ConsecutiveViolations int     `json:"consecutive_violations"` // Consecutive trips required
}

// StepPromotionConfig defines automated step-wise traffic promotion schedule.
type StepPromotionConfig struct {
	AutoPromote     bool          `json:"auto_promote"`
	StepInterval    time.Duration `json:"step_interval"`
	WeightIncrement int           `json:"weight_increment"` // Percentage points to add per step
	TargetWeight    int           `json:"target_weight"`    // Typically 100
}

// CanaryDeployment encapsulates full canary rollout state.
type CanaryDeployment struct {
	ID                  string              `json:"id"`
	Name                string              `json:"name"`
	ServiceName         string              `json:"service_name"`
	BaselineContainerID string              `json:"baseline_container_id"`
	CanaryContainerID   string              `json:"canary_container_id"`
	Phase               CanaryPhase         `json:"phase"`
	Traffic             TrafficSplitConfig  `json:"traffic"`
	Shadow              ShadowMirrorConfig  `json:"shadow"`
	Rollback            RollbackPolicy      `json:"rollback"`
	Promotion           StepPromotionConfig `json:"promotion"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
	PromotedAt          *time.Time          `json:"promoted_at,omitempty"`
	RolledBackAt        *time.Time          `json:"rolled_back_at,omitempty"`
	RollbackReason      string              `json:"rollback_reason,omitempty"`
}

// TrafficDecision holds the calculated target container for an incoming request.
type TrafficDecision struct {
	Target       string `json:"target"` // "baseline" or "canary"
	ContainerID  string `json:"container_id"`
	IsCanary     bool   `json:"is_canary"`
	ShouldMirror bool   `json:"should_mirror"`
	Reason       string `json:"reason"`
	RequestID    string `json:"request_id"`
}

// RequestMetric captures individual request telemetry for divergence detection.
type RequestMetric struct {
	Target     string        `json:"target"` // "baseline", "canary", or "shadow"
	StatusCode int           `json:"status_code"`
	Duration   time.Duration `json:"duration"`
	Timestamp  time.Time     `json:"timestamp"`
	IsError    bool          `json:"is_error"`
}

// CanaryDivergenceReport provides real-time comparative telemetry between baseline and canary.
type CanaryDivergenceReport struct {
	DeploymentID        string    `json:"deployment_id"`
	EvaluatedAt         time.Time `json:"evaluated_at"`
	BaselineSamples     int       `json:"baseline_samples"`
	CanarySamples       int       `json:"canary_samples"`
	ShadowSamples       int       `json:"shadow_samples"`
	BaselineErrorRate   float64   `json:"baseline_error_rate"`    // Percentage (0-100)
	CanaryErrorRate     float64   `json:"canary_error_rate"`      // Percentage (0-100)
	ErrorRateDelta      float64   `json:"error_rate_delta"`       // Canary - Baseline
	BaselineP95LatencyMs float64   `json:"baseline_p95_latency_ms"`
	CanaryP95LatencyMs   float64   `json:"canary_p95_latency_ms"`
	LatencyP95Ratio     float64   `json:"latency_p95_ratio"`      // Canary / Baseline
	Diverged            bool      `json:"diverged"`
	TripReason          string    `json:"trip_reason,omitempty"`
	HealthScore         int       `json:"health_score"`           // 0-100
}

// CanaryConfig holds subsystem-wide configuration defaults.
type CanaryConfig struct {
	Enabled             bool          `json:"enabled"`
	EvaluationInterval  time.Duration `json:"evaluation_interval"`
	DefaultAutoRollback bool          `json:"default_auto_rollback"`
	DefaultShadowMirror bool          `json:"default_shadow_mirror"`
	MaxDeployments      int           `json:"max_deployments"`
}

// CanaryStatus represents global status overview of canary engine.
type CanaryStatus struct {
	Enabled           bool      `json:"enabled"`
	ActiveDeployments int       `json:"active_deployments"`
	TotalDeployments  int       `json:"total_deployments"`
	TotalRoutedReqs   uint64    `json:"total_routed_reqs"`
	TotalMirroredReqs uint64    `json:"total_mirrored_reqs"`
	TotalRollbacks    uint64    `json:"total_rollbacks"`
	LastEvaluationAt  time.Time `json:"last_evaluation_at"`
}

// DefaultCanaryConfig returns safe, resilient default configurations.
func DefaultCanaryConfig() CanaryConfig {
	return CanaryConfig{
		Enabled:             true,
		EvaluationInterval:  5 * time.Second,
		DefaultAutoRollback: true,
		DefaultShadowMirror: true,
		MaxDeployments:      32,
	}
}

// ValidateDeploymentID ensures the canary ID adheres to strict character and length constraints.
func ValidateDeploymentID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" || !validIDRegex.MatchString(id) {
		return fmt.Errorf("%w: must be 1-64 alphanumeric characters, dashes, or dots", ErrInvalidDeploymentID)
	}
	return nil
}

// ValidateWeights ensures baseline and canary weights sum properly and stay within bounds.
func ValidateWeights(baseline, canary int) error {
	if baseline < 0 || baseline > 100 || canary < 0 || canary > 100 {
		return ErrInvalidWeight
	}
	if baseline+canary != 100 {
		return fmt.Errorf("%w: baseline (%d) and canary (%d) must sum to 100", ErrInvalidWeight, baseline, canary)
	}
	return nil
}

// ValidateRollbackPolicy ensures threshold parameters are non-negative and mathematically sound.
func ValidateRollbackPolicy(p RollbackPolicy) error {
	if p.MaxErrorRateDelta < 0 || p.MaxErrorRateDelta > 100 {
		return fmt.Errorf("%w: max error rate delta must be between 0 and 100", ErrInvalidThreshold)
	}
	if p.MaxLatencyP95Ratio <= 0 {
		return fmt.Errorf("%w: max latency ratio must be greater than 0", ErrInvalidThreshold)
	}
	if p.MinSampleSize < 0 {
		return fmt.Errorf("%w: min sample size cannot be negative", ErrInvalidThreshold)
	}
	if p.ConsecutiveViolations <= 0 {
		return fmt.Errorf("%w: consecutive violations must be at least 1", ErrInvalidThreshold)
	}
	return nil
}
