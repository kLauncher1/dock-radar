package canary

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
)

type deploymentInstance struct {
	deployment *CanaryDeployment
	router     *TrafficRouter
	analyzer   *DivergenceAnalyzer
	shadow     *ShadowMirror
}

// Engine manages the end-to-end lifecycle, routing, divergence telemetry, and automated rollbacks for canaries.
type Engine struct {
	config            CanaryConfig
	instances         map[string]*deploymentInstance
	auditLogger       *audit.Logger
	alertDispatcher   *alert.Dispatcher
	totalRoutedReqs   uint64
	totalMirroredReqs uint64
	totalRollbacks    uint64
	lastEvaluationAt  time.Time
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	mu                sync.RWMutex
}

// NewEngine creates a new autonomous Canary & Traffic Mirroring Engine.
func NewEngine(cfg CanaryConfig, auditLogger *audit.Logger, alertDispatcher *alert.Dispatcher) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		config:          cfg,
		instances:       make(map[string]*deploymentInstance),
		auditLogger:     auditLogger,
		alertDispatcher: alertDispatcher,
		ctx:             ctx,
		cancel:          cancel,
	}
}

// Start begins background divergence evaluation and automated promotion/rollback monitoring.
func (e *Engine) Start(parentCtx context.Context) {
	e.mu.Lock()
	if !e.config.Enabled {
		e.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parentCtx)
	e.ctx = ctx
	e.cancel = cancel
	e.mu.Unlock()

	e.wg.Add(1)
	go e.evaluationLoop()
}

// Stop gracefully terminates all background workers and shadow mirroring pools.
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()

	e.mu.Lock()
	defer e.mu.Unlock()
	for _, inst := range e.instances {
		if inst.shadow != nil {
			inst.shadow.Stop()
		}
	}
}

func (e *Engine) evaluationLoop() {
	defer e.wg.Done()
	interval := e.config.EvaluationInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.evaluateAllDeployments()
		}
	}
}

func (e *Engine) evaluateAllDeployments() {
	e.mu.Lock()
	e.lastEvaluationAt = time.Now().UTC()
	instancesCopy := make([]*deploymentInstance, 0, len(e.instances))
	for _, inst := range e.instances {
		instancesCopy = append(instancesCopy, inst)
	}
	e.mu.Unlock()

	for _, inst := range instancesCopy {
		e.evaluateSingleDeployment(inst)
	}
}

func (e *Engine) evaluateSingleDeployment(inst *deploymentInstance) {
	inst.router.mu.RLock()
	phase := inst.deployment.Phase
	depID := inst.deployment.ID
	name := inst.deployment.Name
	canaryWeight := inst.deployment.Traffic.CanaryWeight
	autoRollback := inst.deployment.Rollback.AutoRollback
	promo := inst.deployment.Promotion
	inst.router.mu.RUnlock()

	// Only active or promoting deployments undergo automated evaluation
	if phase != PhaseActive && phase != PhaseEvaluating && phase != PhasePromoting {
		return
	}

	report := inst.analyzer.Evaluate()

	// 1. Divergence tripped -> Trigger automated rollback if enabled
	if report.Diverged {
		if autoRollback {
			_ = e.Rollback(depID, fmt.Sprintf("autonomous rollback: %s", report.TripReason))
			atomic.AddUint64(&e.totalRollbacks, 1)

			// Alert dispatch
			if e.alertDispatcher != nil {
				_ = e.alertDispatcher.Dispatch(e.ctx, alert.Event{
					EventType: "canary_auto_rollback",
					Source:    "canary_engine",
					Level:     alert.LevelCritical,
					Message:   fmt.Sprintf("Autonomous rollback tripped on canary '%s' (%s): %s", name, depID, report.TripReason),
					Timestamp: time.Now().UTC(),
					Details: map[string]any{
						"deployment_id":     depID,
						"error_rate_delta":  report.ErrorRateDelta,
						"latency_p95_ratio": report.LatencyP95Ratio,
						"trip_reason":       report.TripReason,
					},
				})
			}
		}
		return
	}

	// 2. Automated Step-wise Promotion
	if promo.AutoPromote && canaryWeight < promo.TargetWeight {
		newWeight := canaryWeight + promo.WeightIncrement
		if newWeight >= promo.TargetWeight {
			newWeight = promo.TargetWeight
			_ = e.Promote(depID)
		} else {
			_ = e.UpdateWeight(depID, newWeight)
		}
	}
}

// CreateDeployment registers a new canary deployment with validation and shadow mirror worker initialization.
func (e *Engine) CreateDeployment(dep CanaryDeployment) (*CanaryDeployment, error) {
	if err := ValidateDeploymentID(dep.ID); err != nil {
		return nil, err
	}
	if dep.BaselineContainerID == "" || dep.CanaryContainerID == "" {
		return nil, fmt.Errorf("%w: baseline and canary container ids required", ErrInvalidContainerID)
	}
	if err := ValidateWeights(dep.Traffic.BaselineWeight, dep.Traffic.CanaryWeight); err != nil {
		return nil, err
	}
	if err := ValidateRollbackPolicy(dep.Rollback); err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.instances[dep.ID]; exists {
		return nil, ErrDeploymentExists
	}
	if e.config.MaxDeployments > 0 && len(e.instances) >= e.config.MaxDeployments {
		return nil, fmt.Errorf("maximum canary deployments limit (%d) reached", e.config.MaxDeployments)
	}

	now := time.Now().UTC()
	dep.CreatedAt = now
	dep.UpdatedAt = now
	if dep.Phase == "" {
		dep.Phase = PhaseActive
	}

	depCopy := dep
	analyzer := NewDivergenceAnalyzer(dep.ID, dep.Rollback)

	var shadow *ShadowMirror
	if dep.Shadow.Enabled {
		shadow = NewShadowMirror(dep.Shadow, func(deploymentID string, statusCode int, duration time.Duration, isErr bool) {
			analyzer.RecordMetric(RequestMetric{
				Target:     "shadow",
				StatusCode: statusCode,
				Duration:   duration,
				Timestamp:  time.Now().UTC(),
				IsError:    isErr,
			})
			atomic.AddUint64(&e.totalMirroredReqs, 1)
		})
	}

	router := NewTrafficRouter(&depCopy, shadow)

	inst := &deploymentInstance{
		deployment: &depCopy,
		router:     router,
		analyzer:   analyzer,
		shadow:     shadow,
	}

	e.instances[dep.ID] = inst

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  "canary_create",
			Target:  dep.ID,
			Details: map[string]any{"name": dep.Name, "baseline": dep.BaselineContainerID, "canary": dep.CanaryContainerID, "weight": dep.Traffic.CanaryWeight},
		})
	}

	return &depCopy, nil
}

// GetDeployment retrieves a copy of the canary deployment state.
func (e *Engine) GetDeployment(id string) (*CanaryDeployment, error) {
	e.mu.RLock()
	inst, exists := e.instances[id]
	e.mu.RUnlock()

	if !exists {
		return nil, ErrDeploymentNotFound
	}

	inst.router.mu.RLock()
	defer inst.router.mu.RUnlock()
	depCopy := *inst.deployment
	return &depCopy, nil
}

// ListDeployments returns a snapshot list of all registered canaries.
func (e *Engine) ListDeployments() []*CanaryDeployment {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list := make([]*CanaryDeployment, 0, len(e.instances))
	for _, inst := range e.instances {
		inst.router.mu.RLock()
		depCopy := *inst.deployment
		inst.router.mu.RUnlock()
		list = append(list, &depCopy)
	}
	return list
}

// UpdateWeight adjusts traffic distribution dynamically with zero downtime.
func (e *Engine) UpdateWeight(id string, canaryWeight int) error {
	baselineWeight := 100 - canaryWeight
	if err := ValidateWeights(baselineWeight, canaryWeight); err != nil {
		return err
	}

	e.mu.RLock()
	inst, exists := e.instances[id]
	e.mu.RUnlock()

	if !exists {
		return ErrDeploymentNotFound
	}

	err := inst.router.UpdateWeights(baselineWeight, canaryWeight)
	if err != nil {
		return err
	}

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  "canary_weight_update",
			Target:  id,
			Details: map[string]any{"canary_weight": canaryWeight, "baseline_weight": baselineWeight},
		})
	}
	return nil
}

// Promote completes the rollout by shifting 100% traffic to canary and marking phase completed.
func (e *Engine) Promote(id string) error {
	e.mu.RLock()
	inst, exists := e.instances[id]
	e.mu.RUnlock()

	if !exists {
		return ErrDeploymentNotFound
	}

	inst.router.mu.Lock()
	inst.deployment.Traffic.BaselineWeight = 0
	inst.deployment.Traffic.CanaryWeight = 100
	inst.deployment.Phase = PhaseCompleted
	now := time.Now().UTC()
	inst.deployment.PromotedAt = &now
	inst.deployment.UpdatedAt = now
	inst.router.mu.Unlock()

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  "canary_promote",
			Target:  id,
			Details: map[string]any{"phase": PhaseCompleted},
		})
	}
	return nil
}

// Rollback shifts 100% traffic back to baseline and records rollback reason.
func (e *Engine) Rollback(id string, reason string) error {
	e.mu.RLock()
	inst, exists := e.instances[id]
	e.mu.RUnlock()

	if !exists {
		return ErrDeploymentNotFound
	}

	inst.router.mu.Lock()
	inst.deployment.Traffic.BaselineWeight = 100
	inst.deployment.Traffic.CanaryWeight = 0
	inst.deployment.Phase = PhaseRolledBack
	now := time.Now().UTC()
	inst.deployment.RolledBackAt = &now
	inst.deployment.RollbackReason = reason
	inst.deployment.UpdatedAt = now
	inst.router.mu.Unlock()

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  "canary_rollback",
			Target:  id,
			Details: map[string]any{"reason": reason, "phase": PhaseRolledBack},
		})
	}
	return nil
}

// DeleteDeployment removes a canary rollout and terminates associated shadow worker routines.
func (e *Engine) DeleteDeployment(id string) error {
	e.mu.Lock()
	inst, exists := e.instances[id]
	if !exists {
		e.mu.Unlock()
		return ErrDeploymentNotFound
	}
	delete(e.instances, id)
	e.mu.Unlock()

	if inst.shadow != nil {
		inst.shadow.Stop()
	}

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  "canary_delete",
			Target:  id,
		})
	}
	return nil
}

// RouteTraffic resolves routing decision and mirrors traffic asynchronously if shadow mirror is active.
func (e *Engine) RouteTraffic(id string, reqID string, headers map[string]string) (TrafficDecision, error) {
	e.mu.RLock()
	inst, exists := e.instances[id]
	e.mu.RUnlock()

	if !exists {
		return TrafficDecision{}, ErrDeploymentNotFound
	}

	decision := inst.router.Route(reqID, headers)
	atomic.AddUint64(&e.totalRoutedReqs, 1)

	// If shadow mirror is active and request is routed to baseline, duplicate asynchronously to canary
	if decision.ShouldMirror && !decision.IsCanary && inst.shadow != nil {
		inst.shadow.Enqueue(ShadowJob{
			DeploymentID: id,
			RequestID:    reqID,
			TargetURL:    "mock://canary-service",
			Method:       "GET",
			Headers:      headers,
			CreatedAt:    time.Now().UTC(),
		})
	}

	return decision, nil
}

// RecordSample ingests a request telemetry event into the deployment's divergence analyzer.
func (e *Engine) RecordSample(id string, target string, statusCode int, duration time.Duration) error {
	e.mu.RLock()
	inst, exists := e.instances[id]
	e.mu.RUnlock()

	if !exists {
		return ErrDeploymentNotFound
	}

	isErr := statusCode >= 500
	inst.analyzer.RecordMetric(RequestMetric{
		Target:     target,
		StatusCode: statusCode,
		Duration:   duration,
		Timestamp:  time.Now().UTC(),
		IsError:    isErr,
	})
	return nil
}

// GetDivergenceReport generates real-time divergence analysis for a canary deployment.
func (e *Engine) GetDivergenceReport(id string) (*CanaryDivergenceReport, error) {
	e.mu.RLock()
	inst, exists := e.instances[id]
	e.mu.RUnlock()

	if !exists {
		return nil, ErrDeploymentNotFound
	}

	rep := inst.analyzer.Evaluate()
	return &rep, nil
}

// Status returns a high-level summary of the Canary engine.
func (e *Engine) Status() CanaryStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	active := 0
	for _, inst := range e.instances {
		inst.router.mu.RLock()
		if inst.deployment.Phase == PhaseActive || inst.deployment.Phase == PhasePromoting {
			active++
		}
		inst.router.mu.RUnlock()
	}

	return CanaryStatus{
		Enabled:           e.config.Enabled,
		ActiveDeployments: active,
		TotalDeployments:  len(e.instances),
		TotalRoutedReqs:   atomic.LoadUint64(&e.totalRoutedReqs),
		TotalMirroredReqs: atomic.LoadUint64(&e.totalMirroredReqs),
		TotalRollbacks:    atomic.LoadUint64(&e.totalRollbacks),
		LastEvaluationAt:  e.lastEvaluationAt,
	}
}

// Config returns the current engine configuration.
func (e *Engine) Config() CanaryConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

// UpdateConfig updates global engine settings.
func (e *Engine) UpdateConfig(cfg CanaryConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = cfg
}
