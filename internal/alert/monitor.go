package alert

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/system"
)

type containerSnapshot struct {
	ID       string
	Name     string
	State    string
	Status   string
	LastSeen time.Time
}

// ContainerTracker tracks Docker container lifecycles to detect abnormal termination and restart flapping.
type ContainerTracker struct {
	mu         sync.Mutex
	containers map[string]containerSnapshot
	restarts   map[string][]time.Time
}

// NewContainerTracker initializes a stateful container lifecycle tracker.
func NewContainerTracker() *ContainerTracker {
	return &ContainerTracker{
		containers: make(map[string]containerSnapshot),
		restarts:   make(map[string][]time.Time),
	}
}

// EvaluateContainers compares fresh container summaries against previous snapshots.
func (ct *ContainerTracker) EvaluateContainers(
	containers []docker.ContainerSummary,
	flappingWindow time.Duration,
	restartThreshold int,
) []Event {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	var events []Event
	now := time.Now().UTC()
	currentIDs := make(map[string]bool)

	for _, c := range containers {
		currentIDs[c.ID] = true
		containerName := c.ID[:12]
		if len(c.Names) > 0 && c.Names[0] != "" {
			containerName = strings.TrimPrefix(c.Names[0], "/")
		}

		prev, exists := ct.containers[c.ID]
		if exists {
			// 1. Detect Exit Transition: running -> exited or dead
			if prev.State == "running" && (c.State == "exited" || c.State == "dead") {
				level := LevelCritical
				isGraceful := strings.Contains(c.Status, "Exited (0)")
				if isGraceful {
					level = LevelWarning
				}

				events = append(events, Event{
					ID:        generateEventID(),
					Timestamp: now,
					Level:     level,
					Source:    fmt.Sprintf("container:%s", containerName),
					EventType: "container_exit",
					Message: fmt.Sprintf("Container %s transitioned from %s to %s (%s)",
						containerName, prev.State, c.State, c.Status),
					Details: map[string]any{
						"container_id": c.ID,
						"image":        c.Image,
						"prev_state":   prev.State,
						"new_state":    c.State,
						"status":       c.Status,
						"graceful":     isGraceful,
					},
				})
			}

			// 2. Detect Restart / Transition back to running or Restarting state
			restarted := false
			if prev.State != "running" && c.State == "running" {
				restarted = true
			} else if strings.HasPrefix(strings.ToLower(c.Status), "restarting") &&
				!strings.HasPrefix(strings.ToLower(prev.Status), "restarting") {
				restarted = true
			}

			if restarted {
				windowStart := now.Add(-flappingWindow)
				timestamps := ct.restarts[c.ID]

				// Prune outside flapping window
				var pruned []time.Time
				for _, t := range timestamps {
					if t.After(windowStart) {
						pruned = append(pruned, t)
					}
				}
				pruned = append(pruned, now)
				ct.restarts[c.ID] = pruned

				if len(pruned) >= restartThreshold {
					events = append(events, Event{
						ID:        generateEventID(),
						Timestamp: now,
						Level:     LevelCritical,
						Source:    fmt.Sprintf("container:%s", containerName),
						EventType: "restart_flapping",
						Message: fmt.Sprintf("Container %s is flapping (%d restarts within %v)",
							containerName, len(pruned), flappingWindow),
						Details: map[string]any{
							"container_id":  c.ID,
							"image":         c.Image,
							"restart_count": len(pruned),
							"window_sec":    int(flappingWindow.Seconds()),
						},
					})
				}
			}
		}

		// Update snapshot
		ct.containers[c.ID] = containerSnapshot{
			ID:       c.ID,
			Name:     containerName,
			State:    c.State,
			Status:   c.Status,
			LastSeen: now,
		}
	}

	return events
}

// SystemTracker compares system telemetry against resource threshold constraints.
type SystemTracker struct {
	mu           sync.Mutex
	lastReported map[string]time.Time
}

// NewSystemTracker initializes a host system resource tracker.
func NewSystemTracker() *SystemTracker {
	return &SystemTracker{
		lastReported: make(map[string]time.Time),
	}
}

// EvaluateSystem assesses host memory and CPU utilization.
func (st *SystemTracker) EvaluateSystem(metrics system.Metrics, cpuThreshold float64, memThresholdMB float64) []Event {
	return st.EvaluateSystemWithCPU(metrics, 0, cpuThreshold, memThresholdMB)
}

// EvaluateSystemWithCPU evaluates host memory and explicit CPU percentage against thresholds.
func (st *SystemTracker) EvaluateSystemWithCPU(
	metrics system.Metrics,
	cpuPercent float64,
	cpuThreshold float64,
	memThresholdMB float64,
) []Event {
	st.mu.Lock()
	defer st.mu.Unlock()

	var events []Event
	now := time.Now().UTC()

	// Memory evaluation (based on runtime/host allocation)
	if memThresholdMB > 0 && metrics.AllocMB > memThresholdMB {
		level := LevelWarning
		if metrics.AllocMB > memThresholdMB*1.25 {
			level = LevelCritical
		}

		events = append(events, Event{
			ID:        generateEventID(),
			Timestamp: now,
			Level:     level,
			Source:    fmt.Sprintf("system:%s", metrics.Hostname),
			EventType: "memory_threshold",
			Message: fmt.Sprintf("Host memory allocation (%.1f MB) exceeded threshold (%.1f MB)",
				metrics.AllocMB, memThresholdMB),
			Details: map[string]any{
				"alloc_mb":     metrics.AllocMB,
				"sys_mb":       metrics.SysMB,
				"threshold_mb": memThresholdMB,
				"num_gc":       metrics.NumGC,
			},
		})
	}

	// CPU evaluation
	if cpuThreshold > 0 && cpuPercent > cpuThreshold {
		level := LevelWarning
		if cpuPercent > 95.0 {
			level = LevelCritical
		}

		events = append(events, Event{
			ID:        generateEventID(),
			Timestamp: now,
			Level:     level,
			Source:    fmt.Sprintf("system:%s", metrics.Hostname),
			EventType: "cpu_threshold",
			Message: fmt.Sprintf("System CPU usage (%.1f%%) exceeded threshold (%.1f%%)",
				cpuPercent, cpuThreshold),
			Details: map[string]any{
				"cpu_percent":       cpuPercent,
				"threshold_percent": cpuThreshold,
				"num_cpu":           metrics.NumCPU,
				"goroutines":        metrics.NumGoroutine,
			},
		})
	}

	return events
}

// Monitor orchestrates recurring container and host status polling.
type Monitor struct {
	dockerClient     *docker.Client
	configStore      *ConfigStore
	dispatcher       *Dispatcher
	containerTracker *ContainerTracker
	systemTracker    *SystemTracker
	mu               sync.Mutex
}

// NewMonitor creates an alert monitoring engine connecting Docker inspection, system telemetry, and webhook dispatch.
func NewMonitor(dockerClient *docker.Client, configStore *ConfigStore, dispatcher *Dispatcher) *Monitor {
	return &Monitor{
		dockerClient:     dockerClient,
		configStore:      configStore,
		dispatcher:       dispatcher,
		containerTracker: NewContainerTracker(),
		systemTracker:    NewSystemTracker(),
	}
}

// CheckOnce executes a single inspection sweep across containers and host telemetry.
func (m *Monitor) CheckOnce(ctx context.Context) {
	if m.configStore == nil || m.dispatcher == nil {
		return
	}

	cfg := m.configStore.Get()

	// 1. Container inspection
	if m.dockerClient != nil {
		status := m.dockerClient.InspectContainers()
		if status.Available && len(status.Containers) > 0 {
			flappingWindow := time.Duration(cfg.FlappingWindowSeconds) * time.Second
			containerEvents := m.containerTracker.EvaluateContainers(
				status.Containers,
				flappingWindow,
				cfg.RestartThresholdCount,
			)
			for _, evt := range containerEvents {
				_ = m.dispatcher.Dispatch(ctx, evt)
			}
		}
	}

	// 2. System resource inspection
	metrics := system.CollectTelemetry()
	sysEvents := m.systemTracker.EvaluateSystem(metrics, cfg.CPUThresholdPercent, cfg.MemoryThresholdMB)
	for _, evt := range sysEvents {
		_ = m.dispatcher.Dispatch(ctx, evt)
	}
}

// Start launches a periodic polling background loop until ctx is canceled.
func (m *Monitor) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run initial evaluation
	m.CheckOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.CheckOnce(ctx)
		}
	}
}
