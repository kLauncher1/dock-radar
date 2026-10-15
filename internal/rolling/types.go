package rolling

import (
	"errors"
	"strings"
	"time"
)

// Operation and container step lifecycle constants.
const (
	StatusPending    = "pending"
	StatusDraining   = "draining"
	StatusRestarting = "restarting"
	StatusProbing    = "probing"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
	StatusAborted    = "aborted"
	StatusRolledBack = "rolled_back"

	StepPending    = "pending"
	StepDraining   = "draining"
	StepRestarting = "restarting"
	StepProbing    = "probing"
	StepHealthy    = "healthy"
	StepFailed     = "failed"
	StepRolledBack = "rolled_back"

	TargetContainers   = "containers"
	TargetComposeStack = "compose_stack"
	TargetLabel        = "label"
)

var (
	ErrInvalidBatchSize    = errors.New("batch size must be between 1 and 10")
	ErrInvalidDrainTimeout = errors.New("drain timeout must be between 0 and 300 seconds")
	ErrInvalidProbeTimeout = errors.New("probe timeout must be between 3 and 300 seconds")
	ErrNoContainersFound   = errors.New("no active running containers found matching target criteria")
	ErrOperationNotFound   = errors.New("rolling restart operation not found")
	ErrOperationNotActive  = errors.New("operation is not currently active")
	ErrEmptyTarget         = errors.New("target configuration cannot be empty")
)

// RollingPlanConfig specifies the parameters for zero-downtime rolling restart execution.
type RollingPlanConfig struct {
	ID                  string   `json:"id,omitempty"`
	TargetType          string   `json:"target_type"` // containers, compose_stack, label
	TargetValue         string   `json:"target_value,omitempty"`
	ContainerIDs        []string `json:"container_ids,omitempty"`
	BatchSize           int      `json:"batch_size"` // 1 to 10 (default 1)
	DrainTimeoutSec     int      `json:"drain_timeout_sec"` // 0 to 300 (default 5)
	DrainHookURL        string   `json:"drain_hook_url,omitempty"`
	ProbeTimeoutSec     int      `json:"probe_timeout_sec"` // 3 to 300 (default 30)
	ProbeIntervalSec    int      `json:"probe_interval_sec"` // 1 to 30 (default 2)
	HTTPProbePort       int      `json:"http_probe_port,omitempty"`
	HTTPProbePath       string   `json:"http_probe_path,omitempty"` // e.g. /healthz
	ExpectedHTTPStatus  int      `json:"expected_http_status,omitempty"` // default 200
	ReadinessGraceSec   int      `json:"readiness_grace_sec"` // default 2
	AutoRollback        bool     `json:"auto_rollback"` // default true
	MaxFailureThreshold int      `json:"max_failure_threshold"` // default 1
}

// DefaultRollingPlanConfig returns safe defaults for zero-downtime rolling restarts.
func DefaultRollingPlanConfig() RollingPlanConfig {
	return RollingPlanConfig{
		TargetType:          TargetContainers,
		BatchSize:           1,
		DrainTimeoutSec:     5,
		ProbeTimeoutSec:     30,
		ProbeIntervalSec:    2,
		ExpectedHTTPStatus:  200,
		ReadinessGraceSec:   2,
		AutoRollback:        true,
		MaxFailureThreshold: 1,
	}
}

// Validate sanitizes and verifies the rolling plan parameters.
func (cfg *RollingPlanConfig) Validate() error {
	if cfg.TargetType == "" {
		cfg.TargetType = TargetContainers
	}
	switch cfg.TargetType {
	case TargetContainers:
		if len(cfg.ContainerIDs) == 0 {
			return errors.New("container_ids must not be empty when target_type is 'containers'")
		}
	case TargetComposeStack:
		if strings.TrimSpace(cfg.TargetValue) == "" {
			return errors.New("target_value must specify compose project name when target_type is 'compose_stack'")
		}
	case TargetLabel:
		if strings.TrimSpace(cfg.TargetValue) == "" {
			return errors.New("target_value must specify label filter (e.g. app=web) when target_type is 'label'")
		}
	default:
		return errors.New("invalid target_type: must be 'containers', 'compose_stack', or 'label'")
	}

	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 1
	} else if cfg.BatchSize > 10 {
		return ErrInvalidBatchSize
	}

	if cfg.DrainTimeoutSec < 0 || cfg.DrainTimeoutSec > 300 {
		return ErrInvalidDrainTimeout
	}

	if cfg.ProbeTimeoutSec == 0 {
		cfg.ProbeTimeoutSec = 30
	} else if cfg.ProbeTimeoutSec < 3 || cfg.ProbeTimeoutSec > 300 {
		return ErrInvalidProbeTimeout
	}

	if cfg.ProbeIntervalSec <= 0 {
		cfg.ProbeIntervalSec = 2
	} else if cfg.ProbeIntervalSec > 30 {
		cfg.ProbeIntervalSec = 30
	}

	if cfg.ExpectedHTTPStatus <= 0 {
		cfg.ExpectedHTTPStatus = 200
	}

	if cfg.ReadinessGraceSec < 0 {
		cfg.ReadinessGraceSec = 0
	} else if cfg.ReadinessGraceSec > 30 {
		cfg.ReadinessGraceSec = 30
	}

	if cfg.MaxFailureThreshold <= 0 {
		cfg.MaxFailureThreshold = 1
	}

	return nil
}

// ContainerProgress tracks the real-time execution step and health of an individual container.
type ContainerProgress struct {
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	Image         string    `json:"image"`
	Step          string    `json:"step"` // StepPending, StepDraining, StepRestarting, etc.
	StartedAt     time.Time `json:"started_at,omitempty"`
	FinishedAt    time.Time `json:"finished_at,omitempty"`
	Error         string    `json:"error,omitempty"`
	Details       string    `json:"details,omitempty"`
}

// RollingOperation encapsulates the state, progress, and history of a rolling restart plan.
type RollingOperation struct {
	ID               string              `json:"id"`
	Config           RollingPlanConfig   `json:"config"`
	Status           string              `json:"status"` // OperationStatus
	TotalContainers  int                 `json:"total_containers"`
	CompletedCount   int                 `json:"completed_count"`
	FailedCount      int                 `json:"failed_count"`
	CurrentBatch     int                 `json:"current_batch"`
	TotalBatches     int                 `json:"total_batches"`
	Containers       []ContainerProgress `json:"containers"`
	CreatedAt        time.Time           `json:"created_at"`
	StartedAt        time.Time           `json:"started_at,omitempty"`
	CompletedAt      time.Time           `json:"completed_at,omitempty"`
	ErrorMessage     string              `json:"error_message,omitempty"`
}

// RollingStats summarizes metrics across all rolling restart operations.
type RollingStats struct {
	TotalOperations          int64 `json:"total_operations"`
	ActiveOperations         int64 `json:"active_operations"`
	TotalContainersRestarted int64 `json:"total_containers_restarted"`
	TotalContainersFailed    int64 `json:"total_containers_failed"`
	TotalRollbacks           int64 `json:"total_rollbacks"`
}
