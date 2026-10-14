package healing

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
)

// TriggerType constants categorize container failure modes.
const (
	TriggerOOMKilled          = "oom_killed"
	TriggerCrashLoop          = "crash_loop"
	TriggerHealthcheckFailed  = "healthcheck_failed"
)

// ContainerState tracks active remediation, backoff timers, and circuit breakers.
type ContainerState struct {
	ContainerID   string
	ContainerName string
	Image         string
	Attempts      int
	LastAttempt   time.Time
	BackoffUntil  time.Time
	Quarantined   bool
	LastTrigger   string
	Timer         *time.Timer
}

// QuarantinedInfo exposes quarantine status for circuit-broken containers.
type QuarantinedInfo struct {
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	Trigger       string    `json:"trigger"`
	Attempts      int       `json:"attempts"`
	QuarantinedAt time.Time `json:"quarantined_at"`
	Reason        string    `json:"reason"`
}

// HealingStats summarizes real-time remediation metrics.
type HealingStats struct {
	Enabled               bool              `json:"enabled"`
	TotalRemediated       int64             `json:"total_remediated"`
	TotalQuarantined      int64             `json:"total_quarantined"`
	TotalFailed           int64             `json:"total_failed"`
	ActiveBackoffs        int               `json:"active_backoffs"`
	QuarantinedContainers []QuarantinedInfo `json:"quarantined_containers"`
}

// RemediationPlan holds evaluation results for a candidate container.
type RemediationPlan struct {
	ContainerID   string
	ContainerName string
	Image         string
	Trigger       string
	Reason        string
}

// RemediationEngine orchestrates autonomous self-healing policies, backoff jitter, and circuit breakers.
type RemediationEngine struct {
	dockerClient     *docker.Client
	policyStore      *PolicyStore
	history          *HistoryBuffer
	auditLogger      *audit.Logger
	concurrencySem   chan struct{}
	mu               sync.Mutex
	states           map[string]*ContainerState
	totalRemediated  atomic.Int64
	totalQuarantined atomic.Int64
	totalFailed      atomic.Int64
}

// NewRemediationEngine constructs a production-ready container self-healing engine.
func NewRemediationEngine(
	dockerClient *docker.Client,
	policyStore *PolicyStore,
	history *HistoryBuffer,
	auditLogger *audit.Logger,
) *RemediationEngine {
	if history == nil {
		history = NewHistoryBuffer(1000)
	}
	return &RemediationEngine{
		dockerClient:   dockerClient,
		policyStore:    policyStore,
		history:        history,
		auditLogger:    auditLogger,
		concurrencySem: make(chan struct{}, 3), // max 3 concurrent restarts
		states:         make(map[string]*ContainerState),
	}
}

// EvaluateAndRemediate inspects container summaries and executes remediation for failing instances.
func (re *RemediationEngine) EvaluateAndRemediate(containers []docker.ContainerSummary) []RemediationPlan {
	cfg := re.policyStore.Get()
	if !cfg.Enabled {
		return nil
	}

	plans := re.EvaluateContainers(containers)
	for _, plan := range plans {
		re.scheduleRemediation(plan, cfg)
	}
	return plans
}

// EvaluateContainers detects OOM kills, crash loops, and healthcheck failures.
func (re *RemediationEngine) EvaluateContainers(containers []docker.ContainerSummary) []RemediationPlan {
	cfg := re.policyStore.Get()
	if !cfg.Enabled {
		return nil
	}

	excludedMap := make(map[string]bool)
	for _, ex := range cfg.ExcludedContainers {
		excludedMap[strings.ToLower(strings.TrimSpace(ex))] = true
	}

	var plans []RemediationPlan
	for _, c := range containers {
		cName := c.ID[:12]
		if len(c.Names) > 0 && c.Names[0] != "" {
			cName = strings.TrimPrefix(c.Names[0], "/")
		}

		// Check exclusion list and label bypass
		if excludedMap[strings.ToLower(c.ID)] || excludedMap[strings.ToLower(cName)] {
			continue
		}
		if c.Labels != nil && strings.EqualFold(c.Labels["dock-radar.healing"], "false") {
			continue
		}

		statusLower := strings.ToLower(c.Status)
		stateLower := strings.ToLower(c.State)

		// 1. Detect Out-Of-Memory (OOM) killed containers (exit code 137)
		if cfg.AutoRestartOOM {
			if strings.Contains(statusLower, "exited (137)") || strings.Contains(statusLower, "oom") {
				plans = append(plans, RemediationPlan{
					ContainerID:   c.ID,
					ContainerName: cName,
					Image:         c.Image,
					Trigger:       TriggerOOMKilled,
					Reason:        fmt.Sprintf("Container terminated with OOM killer (Status: %s)", c.Status),
				})
				continue
			}
		}

		// 2. Detect Crash Loops / Flapping restarts
		if cfg.AutoRestartCrashLoop {
			if strings.HasPrefix(statusLower, "restarting") || stateLower == "restarting" {
				plans = append(plans, RemediationPlan{
					ContainerID:   c.ID,
					ContainerName: cName,
					Image:         c.Image,
					Trigger:       TriggerCrashLoop,
					Reason:        fmt.Sprintf("Container caught in restart loop (Status: %s)", c.Status),
				})
				continue
			}
		}

		// 3. Detect Unhealthy Healthcheck statuses
		if cfg.AutoRemediateUnhealthy {
			if strings.Contains(statusLower, "(unhealthy)") || stateLower == "unhealthy" {
				plans = append(plans, RemediationPlan{
					ContainerID:   c.ID,
					ContainerName: cName,
					Image:         c.Image,
					Trigger:       TriggerHealthcheckFailed,
					Reason:        fmt.Sprintf("Container healthcheck reported unhealthy (Status: %s)", c.Status),
				})
				continue
			}
		}
	}

	return plans
}

func (re *RemediationEngine) scheduleRemediation(plan RemediationPlan, cfg PolicyConfig) {
	re.mu.Lock()
	defer re.mu.Unlock()

	now := time.Now().UTC()
	st, exists := re.states[plan.ContainerID]
	if !exists {
		st = &ContainerState{
			ContainerID:   plan.ContainerID,
			ContainerName: plan.ContainerName,
			Image:         plan.Image,
		}
		re.states[plan.ContainerID] = st
	}

	// Reset attempts if cooldown elapsed
	if !st.LastAttempt.IsZero() && now.Sub(st.LastAttempt) > time.Duration(cfg.CooldownSec)*time.Second {
		st.Attempts = 0
		st.Quarantined = false
	}

	// Rollback Protection / Circuit Breaker check
	if st.Quarantined {
		return
	}

	if st.Attempts >= cfg.MaxAttempts {
		st.Quarantined = true
		st.LastAttempt = now
		re.totalQuarantined.Add(1)

		event := RemediationEvent{
			Timestamp:     now,
			ContainerID:   plan.ContainerID,
			ContainerName: plan.ContainerName,
			Image:         plan.Image,
			Trigger:       plan.Trigger,
			Attempt:       st.Attempts,
			Action:        "quarantine",
			Status:        "quarantined",
			Message:       fmt.Sprintf("Circuit breaker tripped: exceeded %d attempts. Quarantined to prevent thrashing.", cfg.MaxAttempts),
			Details: map[string]any{
				"reason": plan.Reason,
			},
		}
		re.history.Record(event)

		if re.auditLogger != nil {
			re.auditLogger.Log(audit.AuditEvent{
				Action:  "healing_quarantine",
				Target:  plan.ContainerName,
				Details: map[string]any{"container_id": plan.ContainerID, "trigger": plan.Trigger},
			})
		}
		return
	}

	// Check if already in active backoff
	if now.Before(st.BackoffUntil) {
		return
	}

	st.Attempts++
	st.LastAttempt = now
	st.LastTrigger = plan.Trigger

	backoff := CalculateBackoff(st.Attempts, cfg.BaseBackoffSec, cfg.MaxBackoffSec, cfg.JitterFactor)
	st.BackoffUntil = now.Add(backoff)

	scheduledEvent := RemediationEvent{
		Timestamp:     now,
		ContainerID:   plan.ContainerID,
		ContainerName: plan.ContainerName,
		Image:         plan.Image,
		Trigger:       plan.Trigger,
		Attempt:       st.Attempts,
		BackoffSec:    backoff.Seconds(),
		Action:        "scheduled",
		Status:        "in_progress",
		Message:       fmt.Sprintf("Remediation attempt %d scheduled with %s backoff jitter (%s)", st.Attempts, FormatDuration(backoff), plan.Reason),
	}
	re.history.Record(scheduledEvent)

	// Launch async execution after backoff jitter
	go re.executeRestartAfterBackoff(plan, st.Attempts, backoff)
}

func (re *RemediationEngine) executeRestartAfterBackoff(plan RemediationPlan, attempt int, backoff time.Duration) {
	time.Sleep(backoff)

	// Acquire concurrency semaphore to prevent daemon saturation
	select {
	case re.concurrencySem <- struct{}{}:
		defer func() { <-re.concurrencySem }()
	case <-time.After(30 * time.Second):
		// Abort on timeout
		re.history.Record(RemediationEvent{
			Timestamp:     time.Now().UTC(),
			ContainerID:   plan.ContainerID,
			ContainerName: plan.ContainerName,
			Image:         plan.Image,
			Trigger:       plan.Trigger,
			Attempt:       attempt,
			Action:        "abort",
			Status:        "failed",
			Message:       "Remediation aborted: daemon concurrency semaphore timeout",
		})
		re.totalFailed.Add(1)
		return
	}

	// Perform restart
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	var err error
	if re.dockerClient != nil {
		err = re.dockerClient.RestartContainer(ctx, plan.ContainerID, 10)
	}

	now := time.Now().UTC()
	if err != nil {
		re.totalFailed.Add(1)
		re.history.Record(RemediationEvent{
			Timestamp:     now,
			ContainerID:   plan.ContainerID,
			ContainerName: plan.ContainerName,
			Image:         plan.Image,
			Trigger:       plan.Trigger,
			Attempt:       attempt,
			Action:        "restart",
			Status:        "failed",
			Message:       fmt.Sprintf("Restart failed: %v", err),
		})
	} else {
		re.totalRemediated.Add(1)
		re.history.Record(RemediationEvent{
			Timestamp:     now,
			ContainerID:   plan.ContainerID,
			ContainerName: plan.ContainerName,
			Image:         plan.Image,
			Trigger:       plan.Trigger,
			Attempt:       attempt,
			Action:        "restart",
			Status:        "success",
			Message:       fmt.Sprintf("Container successfully restarted via autonomous self-healing policy (%s)", plan.Trigger),
		})

		if re.auditLogger != nil {
			re.auditLogger.Log(audit.AuditEvent{
				Action:  "healing_restarted",
				Target:  plan.ContainerName,
				Details: map[string]any{"container_id": plan.ContainerID, "trigger": plan.Trigger, "attempt": attempt},
			})
		}
	}
}

// ResetContainer clears quarantine and backoff state for the specified container.
func (re *RemediationEngine) ResetContainer(containerID string) bool {
	re.mu.Lock()
	defer re.mu.Unlock()

	containerID = strings.TrimSpace(containerID)
	found := false
	for k, st := range re.states {
		if strings.EqualFold(k, containerID) || strings.EqualFold(st.ContainerName, containerID) {
			delete(re.states, k)
			found = true
			re.history.Record(RemediationEvent{
				Timestamp:     time.Now().UTC(),
				ContainerID:   st.ContainerID,
				ContainerName: st.ContainerName,
				Action:        "reset",
				Status:        "success",
				Message:       "Circuit breaker and backoff state manually cleared by operator",
			})
		}
	}
	return found
}

// ResetAll resets state across all tracked containers.
func (re *RemediationEngine) ResetAll() {
	re.mu.Lock()
	defer re.mu.Unlock()

	re.states = make(map[string]*ContainerState)
	re.history.Record(RemediationEvent{
		Timestamp: time.Now().UTC(),
		Action:    "reset_all",
		Status:    "success",
		Message:   "All healing circuit breakers and quarantine states reset by operator",
	})
}

// Stats returns a snapshot of current healing operations.
func (re *RemediationEngine) Stats() HealingStats {
	re.mu.Lock()
	defer re.mu.Unlock()

	cfg := re.policyStore.Get()
	now := time.Now().UTC()

	var quarantined []QuarantinedInfo
	activeBackoffs := 0

	for _, st := range re.states {
		if st.Quarantined {
			quarantined = append(quarantined, QuarantinedInfo{
				ContainerID:   st.ContainerID,
				ContainerName: st.ContainerName,
				Trigger:       st.LastTrigger,
				Attempts:      st.Attempts,
				QuarantinedAt: st.LastAttempt,
				Reason:        fmt.Sprintf("Exceeded maximum threshold of %d attempts", cfg.MaxAttempts),
			})
		} else if now.Before(st.BackoffUntil) {
			activeBackoffs++
		}
	}

	return HealingStats{
		Enabled:               cfg.Enabled,
		TotalRemediated:       re.totalRemediated.Load(),
		TotalQuarantined:      re.totalQuarantined.Load(),
		TotalFailed:           re.totalFailed.Load(),
		ActiveBackoffs:        activeBackoffs,
		QuarantinedContainers: quarantined,
	}
}

// History returns the attached HistoryBuffer.
func (re *RemediationEngine) History() *HistoryBuffer {
	return re.history
}

// PolicyStore returns the attached PolicyStore.
func (re *RemediationEngine) PolicyStore() *PolicyStore {
	return re.policyStore
}

// Start launches a periodic background loop inspecting containers and applying healing policies.
func (re *RemediationEngine) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if re.dockerClient != nil {
				status := re.dockerClient.InspectContainers()
				if status.Available && len(status.Containers) > 0 {
					re.EvaluateAndRemediate(status.Containers)
				}
			}
		}
	}
}

