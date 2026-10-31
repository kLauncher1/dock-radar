package canary

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"hash/fnv"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ShadowJob holds data for asynchronous shadow mirroring.
type ShadowJob struct {
	DeploymentID string
	RequestID    string
	TargetURL    string
	Method       string
	Headers      map[string]string
	Payload      []byte
	CreatedAt    time.Time
}

// ShadowWorkerCallback defines the hook called when a shadow mirrored request completes.
type ShadowWorkerCallback func(deploymentID string, statusCode int, duration time.Duration, isErr bool)

// ShadowMirror manages asynchronous, non-blocking duplication of requests to canary instances.
type ShadowMirror struct {
	config       ShadowMirrorConfig
	jobQueue     chan ShadowJob
	droppedJobs  uint64
	processedJobs uint64
	callback     ShadowWorkerCallback
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	mu           sync.RWMutex
}

// NewShadowMirror initializes a worker pool for non-blocking shadow traffic duplication.
func NewShadowMirror(cfg ShadowMirrorConfig, cb ShadowWorkerCallback) *ShadowMirror {
	if cfg.MaxQueueSize <= 0 {
		cfg.MaxQueueSize = 1000
	}
	if cfg.WorkerConcurrency <= 0 {
		cfg.WorkerConcurrency = 4
	}
	if cfg.TimeoutMs <= 0 {
		cfg.TimeoutMs = 2000
	}
	if cfg.SampleRate <= 0.0 {
		cfg.SampleRate = 1.0
	}

	ctx, cancel := context.WithCancel(context.Background())
	sm := &ShadowMirror{
		config:   cfg,
		jobQueue: make(chan ShadowJob, cfg.MaxQueueSize),
		callback: cb,
		ctx:      ctx,
		cancel:   cancel,
	}

	sm.startWorkers()
	return sm
}

func (sm *ShadowMirror) startWorkers() {
	for i := 0; i < sm.config.WorkerConcurrency; i++ {
		sm.wg.Add(1)
		go sm.workerLoop()
	}
}

func (sm *ShadowMirror) workerLoop() {
	defer sm.wg.Done()
	client := &http.Client{
		Timeout: time.Duration(sm.config.TimeoutMs) * time.Millisecond,
	}

	for {
		select {
		case <-sm.ctx.Done():
			return
		case job, ok := <-sm.jobQueue:
			if !ok {
				return
			}
			sm.processJob(client, job)
		}
	}
}

func (sm *ShadowMirror) processJob(client *http.Client, job ShadowJob) {
	start := time.Now()
	atomic.AddUint64(&sm.processedJobs, 1)

	// In real or simulated container networks, if TargetURL is empty or mock, treat as simulated mirror
	if job.TargetURL == "" || strings.HasPrefix(job.TargetURL, "mock://") {
		// Mock shadow delivery latency
		duration := time.Since(start)
		if sm.callback != nil {
			sm.callback(job.DeploymentID, http.StatusOK, duration, false)
		}
		return
	}

	req, err := http.NewRequestWithContext(sm.ctx, job.Method, job.TargetURL, nil)
	if err != nil {
		if sm.callback != nil {
			sm.callback(job.DeploymentID, http.StatusInternalServerError, time.Since(start), true)
		}
		return
	}

	for k, v := range job.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-Shadow-Mirrored", "true")

	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		if sm.callback != nil {
			sm.callback(job.DeploymentID, http.StatusBadGateway, duration, true)
		}
		return
	}
	_ = resp.Body.Close()

	isErr := resp.StatusCode >= 500
	if sm.callback != nil {
		sm.callback(job.DeploymentID, resp.StatusCode, duration, isErr)
	}
}

// Enqueue attempts to dispatch a shadow request. Returns true if queued, false if dropped due to capacity.
func (sm *ShadowMirror) Enqueue(job ShadowJob) bool {
	sm.mu.RLock()
	enabled := sm.config.Enabled
	rate := sm.config.SampleRate
	sm.mu.RUnlock()

	if !enabled {
		return false
	}

	// Sample rate filtering
	if rate < 1.0 {
		var b [2]byte
		_, _ = rand.Read(b[:])
		val := float64(binary.BigEndian.Uint16(b[:])) / 65535.0
		if val > rate {
			return false
		}
	}

	select {
	case sm.jobQueue <- job:
		return true
	default:
		atomic.AddUint64(&sm.droppedJobs, 1)
		return false
	}
}

// Stop gracefully shuts down shadow mirror workers.
func (sm *ShadowMirror) Stop() {
	sm.cancel()
	sm.wg.Wait()
}

// Stats returns dropped and processed job counts.
func (sm *ShadowMirror) Stats() (processed uint64, dropped uint64) {
	return atomic.LoadUint64(&sm.processedJobs), atomic.LoadUint64(&sm.droppedJobs)
}

// UpdateConfig modifies shadow mirror settings dynamically without dropping worker pool.
func (sm *ShadowMirror) UpdateConfig(cfg ShadowMirrorConfig) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.config = cfg
}

// TrafficRouter calculates traffic split decisions with zero packet loss and sticky session affinity.
type TrafficRouter struct {
	deployment *CanaryDeployment
	shadow     *ShadowMirror
	mu         sync.RWMutex
}

// NewTrafficRouter constructs a thread-safe traffic router for a canary deployment.
func NewTrafficRouter(dep *CanaryDeployment, shadow *ShadowMirror) *TrafficRouter {
	return &TrafficRouter{
		deployment: dep,
		shadow:     shadow,
	}
}

// Route determines target container for an incoming request based on weights and affinity headers.
func (tr *TrafficRouter) Route(reqID string, headers map[string]string) TrafficDecision {
	tr.mu.RLock()
	dep := tr.deployment
	traffic := dep.Traffic
	shadowCfg := dep.Shadow
	phase := dep.Phase
	tr.mu.RUnlock()

	decision := TrafficDecision{
		RequestID:    reqID,
		ShouldMirror: shadowCfg.Enabled,
	}

	// 1. If deployment is not active or is rolled back, 100% baseline
	if phase == PhaseRolledBack || phase == PhaseFailed || phase == PhasePending {
		decision.Target = "baseline"
		decision.ContainerID = dep.BaselineContainerID
		decision.IsCanary = false
		decision.Reason = "deployment_inactive_fallback_baseline"
		return decision
	}

	// 2. If completed, 100% canary
	if phase == PhaseCompleted || traffic.CanaryWeight >= 100 {
		decision.Target = "canary"
		decision.ContainerID = dep.CanaryContainerID
		decision.IsCanary = true
		decision.Reason = "deployment_completed_100_percent_canary"
		return decision
	}

	// 3. Header override check (e.g. X-Canary-Force: true)
	if traffic.CanaryHeaderOverride != "" && headers != nil {
		val := headers[traffic.CanaryHeaderOverride]
		if strings.EqualFold(val, "true") || val == "1" {
			decision.Target = "canary"
			decision.ContainerID = dep.CanaryContainerID
			decision.IsCanary = true
			decision.Reason = "header_override_forced_canary"
			return decision
		}
	}

	// 4. Sticky Session Header Affinity check (e.g. X-User-ID, X-Session-ID)
	if traffic.HeaderAffinity != "" && headers != nil {
		if affVal, ok := headers[traffic.HeaderAffinity]; ok && affVal != "" {
			h := fnv.New32a()
			_, _ = h.Write([]byte(affVal))
			bucket := int(h.Sum32() % 100)
			if bucket < traffic.CanaryWeight {
				decision.Target = "canary"
				decision.ContainerID = dep.CanaryContainerID
				decision.IsCanary = true
				decision.Reason = "sticky_affinity_bucket_canary"
			} else {
				decision.Target = "baseline"
				decision.ContainerID = dep.BaselineContainerID
				decision.IsCanary = false
				decision.Reason = "sticky_affinity_bucket_baseline"
			}
			return decision
		}
	}

	// 5. Dynamic Weighted Random Split
	var b [2]byte
	_, _ = rand.Read(b[:])
	val := int(binary.BigEndian.Uint16(b[:]) % 100)

	if val < traffic.CanaryWeight {
		decision.Target = "canary"
		decision.ContainerID = dep.CanaryContainerID
		decision.IsCanary = true
		decision.Reason = "weighted_split_canary"
	} else {
		decision.Target = "baseline"
		decision.ContainerID = dep.BaselineContainerID
		decision.IsCanary = false
		decision.Reason = "weighted_split_baseline"
	}

	return decision
}

// UpdateWeights updates traffic weights atomically with zero downtime.
func (tr *TrafficRouter) UpdateWeights(baseline, canary int) error {
	if err := ValidateWeights(baseline, canary); err != nil {
		return err
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.deployment.Traffic.BaselineWeight = baseline
	tr.deployment.Traffic.CanaryWeight = canary
	tr.deployment.UpdatedAt = time.Now().UTC()
	return nil
}

// UpdatePhase transitions deployment phase safely.
func (tr *TrafficRouter) UpdatePhase(phase CanaryPhase) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.deployment.Phase = phase
	tr.deployment.UpdatedAt = time.Now().UTC()
}

// Shadow returns the underlying shadow mirror instance.
func (tr *TrafficRouter) Shadow() *ShadowMirror {
	return tr.shadow
}
