package rolling

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
)

// Engine coordinates zero-downtime rolling restart pipelines, traffic draining, and rollbacks.
type Engine struct {
	dockerClient             *docker.Client
	auditLogger              *audit.Logger
	alertDispatcher          *alert.Dispatcher
	store                    *Store
	drainer                  *DrainController
	prober                   *ReadinessProber
	mu                       sync.Mutex
	activeCancels            map[string]context.CancelFunc
	totalOperations          atomic.Int64
	activeOperations         atomic.Int64
	totalContainersRestarted atomic.Int64
	totalContainersFailed    atomic.Int64
	totalRollbacks           atomic.Int64
}

// NewEngine creates an operational rolling restart orchestrator.
func NewEngine(
	dockerClient *docker.Client,
	auditLogger *audit.Logger,
	alertDispatcher *alert.Dispatcher,
) *Engine {
	store := NewStore(200)
	drainer := NewDrainController(nil)
	prober := NewReadinessProber(dockerClient, nil)

	return &Engine{
		dockerClient:    dockerClient,
		auditLogger:     auditLogger,
		alertDispatcher: alertDispatcher,
		store:           store,
		drainer:         drainer,
		prober:          prober,
		activeCancels:   make(map[string]context.CancelFunc),
	}
}

// Store returns the backing in-memory store.
func (e *Engine) Store() *Store {
	return e.store
}

// Stats returns atomic metrics across rolling restart operations.
func (e *Engine) Stats() RollingStats {
	return RollingStats{
		TotalOperations:          e.totalOperations.Load(),
		ActiveOperations:         e.activeOperations.Load(),
		TotalContainersRestarted: e.totalContainersRestarted.Load(),
		TotalContainersFailed:    e.totalContainersFailed.Load(),
		TotalRollbacks:           e.totalRollbacks.Load(),
	}
}

// StartOperation resolves matching containers and kicks off an asynchronous rolling restart.
func (e *Engine) StartOperation(ctx context.Context, cfg RollingPlanConfig) (*RollingOperation, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Step 1: Query Docker daemon to resolve target containers
	status := e.dockerClient.InspectContainers()
	matchingContainers := e.resolveTargets(status.Containers, cfg)
	if len(matchingContainers) == 0 {
		return nil, ErrNoContainersFound
	}

	// Step 2: Generate operation identifier
	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)
	opID := fmt.Sprintf("roll-%s-%s", time.Now().Format("150405"), hex.EncodeToString(randBytes))
	cfg.ID = opID

	// Step 3: Partition containers into batches
	totalContainers := len(matchingContainers)
	totalBatches := (totalContainers + cfg.BatchSize - 1) / cfg.BatchSize

	var progressList []ContainerProgress
	for _, c := range matchingContainers {
		name := c.ID
		if len(name) > 12 {
			name = name[:12]
		}
		if len(c.Names) > 0 && c.Names[0] != "" {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		progressList = append(progressList, ContainerProgress{
			ContainerID:   c.ID,
			ContainerName: name,
			Image:         c.Image,
			Step:          StepPending,
		})
	}

	op := &RollingOperation{
		ID:              opID,
		Config:          cfg,
		Status:          StatusPending,
		TotalContainers: totalContainers,
		CompletedCount:  0,
		FailedCount:     0,
		CurrentBatch:    0,
		TotalBatches:    totalBatches,
		Containers:      progressList,
		CreatedAt:       time.Now().UTC(),
	}

	e.store.Save(op)
	e.totalOperations.Add(1)
	e.activeOperations.Add(1)

	// Step 4: Launch background executor with cancellable context
	opCtx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.activeCancels[opID] = cancel
	e.mu.Unlock()

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action: "rolling_restart_started",
			Target: opID,
			Details: map[string]any{
				"target_type":      cfg.TargetType,
				"target_value":     cfg.TargetValue,
				"total_containers": totalContainers,
				"batch_size":       cfg.BatchSize,
				"auto_rollback":    cfg.AutoRollback,
			},
		})
	}

	go e.runRollingLoop(opCtx, op)

	return op, nil
}

// AbortOperation cancels an active rolling restart execution.
func (e *Engine) AbortOperation(id string) error {
	e.mu.Lock()
	cancel, found := e.activeCancels[id]
	if !found {
		e.mu.Unlock()
		return ErrOperationNotActive
	}
	delete(e.activeCancels, id)
	e.mu.Unlock()

	cancel()

	if op, ok := e.store.Get(id); ok {
		op.Status = StatusAborted
		op.CompletedAt = time.Now().UTC()
		op.ErrorMessage = "operation manually aborted by administrator"
		e.store.Save(op)
	}

	e.activeOperations.Add(-1)

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  "rolling_restart_aborted",
			Target:  id,
			Details: map[string]any{"reason": "manual_abort"},
		})
	}

	return nil
}

func (e *Engine) runRollingLoop(ctx context.Context, op *RollingOperation) {
	defer func() {
		e.mu.Lock()
		delete(e.activeCancels, op.ID)
		e.mu.Unlock()
		e.activeOperations.Add(-1)
	}()

	op.Status = StatusDraining
	op.StartedAt = time.Now().UTC()
	e.store.Save(op)

	batchSize := op.Config.BatchSize
	total := len(op.Containers)

	for i := 0; i < total; i += batchSize {
		select {
		case <-ctx.Done():
			op.Status = StatusAborted
			op.CompletedAt = time.Now().UTC()
			op.ErrorMessage = "operation aborted during batch execution"
			e.store.Save(op)
			return
		default:
		}

		end := i + batchSize
		if end > total {
			end = total
		}

		op.CurrentBatch = (i / batchSize) + 1
		e.store.Save(op)

		// Process each container in current batch
		for idx := i; idx < end; idx++ {
			c := &op.Containers[idx]
			c.StartedAt = time.Now().UTC()

			// Sub-step 1: Drain traffic
			c.Step = StepDraining
			op.Status = StatusDraining
			e.store.Save(op)

			if err := e.drainer.Drain(ctx, *c, op.Config); err != nil {
				if ctx.Err() != nil {
					return
				}
				c.Details = fmt.Sprintf("drain warning: %v", err)
			}

			// Sub-step 2: Restart container
			c.Step = StepRestarting
			op.Status = StatusRestarting
			e.store.Save(op)

			restartErr := e.dockerClient.RestartContainer(ctx, c.ContainerID, 10)
			if restartErr != nil {
				c.Step = StepFailed
				c.Error = fmt.Sprintf("restart failed: %v", restartErr)
				c.FinishedAt = time.Now().UTC()
				op.FailedCount++
				e.totalContainersFailed.Add(1)
				e.store.Save(op)

				e.handleFailure(ctx, op, c)
				return
			}

			// Sub-step 3: Probe readiness
			c.Step = StepProbing
			op.Status = StatusProbing
			e.store.Save(op)

			probeErr := e.prober.WaitForReady(ctx, c.ContainerID, op.Config)
			if probeErr != nil {
				c.Step = StepFailed
				c.Error = fmt.Sprintf("readiness probe failed: %v", probeErr)
				c.FinishedAt = time.Now().UTC()
				op.FailedCount++
				e.totalContainersFailed.Add(1)
				e.store.Save(op)

				e.handleFailure(ctx, op, c)
				return
			}

			// Sub-step 4: Ready and Undrain
			c.Step = StepHealthy
			c.FinishedAt = time.Now().UTC()
			op.CompletedCount++
			e.totalContainersRestarted.Add(1)
			_ = e.drainer.Undrain(ctx, *c, op.Config)
			e.store.Save(op)
		}
	}

	op.Status = StatusCompleted
	op.CompletedAt = time.Now().UTC()
	e.store.Save(op)

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action: "rolling_restart_completed",
			Target: op.ID,
			Details: map[string]any{
				"completed_count": op.CompletedCount,
				"failed_count":    op.FailedCount,
			},
		})
	}
}

func (e *Engine) handleFailure(ctx context.Context, op *RollingOperation, failedContainer *ContainerProgress) {
	if op.FailedCount >= op.Config.MaxFailureThreshold {
		if op.Config.AutoRollback {
			op.Status = StatusRolledBack
			e.totalRollbacks.Add(1)
			failedContainer.Step = StepRolledBack
			failedContainer.Details = "auto-rollback triggered after failure"
		} else {
			op.Status = StatusFailed
		}
		op.CompletedAt = time.Now().UTC()
		op.ErrorMessage = fmt.Sprintf("aborted due to failure in container %s: %s", failedContainer.ContainerName, failedContainer.Error)
		e.store.Save(op)

		// Dispatch high priority alert
		if e.alertDispatcher != nil {
			_ = e.alertDispatcher.Dispatch(ctx, alert.Event{
				Level:     alert.LevelCritical,
				Source:    failedContainer.ContainerName,
				EventType: "rolling_restart_failure",
				Message:   fmt.Sprintf("Rolling restart plan %s halted. Container %s failed readiness probe: %s", op.ID, failedContainer.ContainerName, failedContainer.Error),
				Timestamp: time.Now().UTC(),
				Details: map[string]any{
					"operation_id": op.ID,
					"container_id": failedContainer.ContainerID,
					"error":        failedContainer.Error,
				},
			})
		}

		if e.auditLogger != nil {
			e.auditLogger.Log(audit.AuditEvent{
				Action: "rolling_restart_aborted_failure",
				Target: op.ID,
				Details: map[string]any{
					"failed_container": failedContainer.ContainerID,
					"error":            failedContainer.Error,
					"auto_rollback":    op.Config.AutoRollback,
				},
			})
		}
	}
}

func (e *Engine) resolveTargets(containers []docker.ContainerSummary, cfg RollingPlanConfig) []docker.ContainerSummary {
	var matched []docker.ContainerSummary

	switch cfg.TargetType {
	case TargetContainers:
		idSet := make(map[string]bool)
		for _, id := range cfg.ContainerIDs {
			idSet[strings.ToLower(strings.TrimSpace(id))] = true
		}
		for _, c := range containers {
			cName := c.ID
			if len(cName) > 12 {
				cName = cName[:12]
			}
			if len(c.Names) > 0 && c.Names[0] != "" {
				cName = strings.TrimPrefix(c.Names[0], "/")
			}
			if idSet[strings.ToLower(c.ID)] || idSet[strings.ToLower(cName)] {
				matched = append(matched, c)
			}
		}

	case TargetComposeStack:
		targetProject := strings.ToLower(strings.TrimSpace(cfg.TargetValue))
		for _, c := range containers {
			if c.Labels != nil {
				proj := strings.ToLower(strings.TrimSpace(c.Labels["com.docker.compose.project"]))
				if proj == targetProject {
					matched = append(matched, c)
				}
			}
		}

	case TargetLabel:
		parts := strings.SplitN(cfg.TargetValue, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			for _, c := range containers {
				if c.Labels != nil && c.Labels[k] == v {
					matched = append(matched, c)
				}
			}
		}
	}

	return matched
}
