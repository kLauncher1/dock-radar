package anomaly

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/system"
)

// AnomalySummary provides an aggregated operational radar snapshot of container exhaustion risks.
type AnomalySummary struct {
	MonitoredContainers   int       `json:"monitored_containers"`
	StableCount           int       `json:"stable_count"`
	ModerateGrowthCount   int       `json:"moderate_growth_count"`
	WarningCount          int       `json:"warning_count"`
	CriticalCount         int       `json:"critical_count"`
	FastestGrowingName    string    `json:"fastest_growing_name,omitempty"`
	FastestGrowingRateMBs float64   `json:"fastest_growing_rate_mbs"`
	ShortestSecondsToOOM  float64   `json:"shortest_seconds_to_oom"`
	CheckedAt             time.Time `json:"checked_at"`
}

// Detector orchestrates background resource polling, linear regression trend tracking, and alarms.
type Detector struct {
	mu            sync.RWMutex
	dockerClient  *docker.Client
	store         *TrackerStore
	alarms        *AlarmManager
	dispatcher    *alert.Dispatcher
	lastSummary   AnomalySummary
	fallbackLimit uint64
	isRunning     bool
	stopCh        chan struct{}
}

// NewDetector initializes a new anomaly detection engine.
func NewDetector(dockerClient *docker.Client, dispatcher *alert.Dispatcher) *Detector {
	store := NewTrackerStore(500, 60)
	alarms := NewAlarmManager(DefaultAlarmConfig(), 200)

	// Fetch host physical memory as default fallback limit for containers without explicit memory limits
	var fallbackLimit uint64 = 1024 * 1024 * 1024 // 1 GB fallback
	telemetry := system.CollectTelemetry()
	if telemetry.SysMB > 0 {
		fallbackLimit = uint64(telemetry.SysMB * 1024 * 1024)
	}

	return &Detector{
		dockerClient:  dockerClient,
		store:         store,
		alarms:        alarms,
		dispatcher:    dispatcher,
		fallbackLimit: fallbackLimit,
		stopCh:        make(chan struct{}),
	}
}

// Start launches the continuous anomaly detection ticker loop.
func (d *Detector) Start(ctx context.Context, interval time.Duration) {
	d.mu.Lock()
	if d.isRunning {
		d.mu.Unlock()
		return
	}
	d.isRunning = true
	d.mu.Unlock()

	if interval <= 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial immediate sweep
	_, _ = d.SampleOnce(ctx)

	pruneCounter := 0
	for {
		select {
		case <-ctx.Done():
			d.mu.Lock()
			d.isRunning = false
			d.mu.Unlock()
			return
		case <-d.stopCh:
			d.mu.Lock()
			d.isRunning = false
			d.mu.Unlock()
			return
		case <-ticker.C:
			_, _ = d.SampleOnce(ctx)

			pruneCounter++
			if pruneCounter >= 120 { // Roughly every 10 minutes
				d.store.PruneStale(1 * time.Hour)
				pruneCounter = 0
			}
		}
	}
}

// Stop cleanly terminates the background monitoring ticker.
func (d *Detector) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.isRunning {
		close(d.stopCh)
		d.isRunning = false
	}
}

// SampleOnce gathers current resource metrics, computes regressions, and evaluates early alarms.
func (d *Detector) SampleOnce(ctx context.Context) ([]TrendPrediction, error) {
	if d.dockerClient == nil {
		return nil, nil
	}

	statsList := d.dockerClient.InspectAllContainerStats(ctx)
	if len(statsList) == 0 {
		return nil, nil
	}

	var predictions []TrendPrediction
	summary := AnomalySummary{
		MonitoredContainers:  len(statsList),
		ShortestSecondsToOOM: -1.0,
		CheckedAt:            time.Now().UTC(),
	}

	for _, st := range statsList {
		sample := MetricSample{
			Timestamp:   st.Timestamp,
			MemoryBytes: st.MemoryUsage,
			MemoryLimit: st.MemoryLimit,
			CPUPercent:  st.CPUPercent,
		}

		d.store.RecordMetric(st.ID, st.Name, sample)
		series, ok := d.store.GetSeries(st.ID)
		if !ok {
			continue
		}

		samples := series.Samples()
		pred := PredictExhaustion(st.ID, st.Name, samples, d.fallbackLimit)
		predictions = append(predictions, pred)

		// Evaluate early warning alarm
		d.alarms.EvaluateAndDispatch(pred, d.dispatcher)

		// Aggregate summary counts
		switch pred.Category {
		case ExhaustionCritical:
			summary.CriticalCount++
			if summary.ShortestSecondsToOOM < 0 || pred.SecondsToOOM < summary.ShortestSecondsToOOM {
				summary.ShortestSecondsToOOM = pred.SecondsToOOM
			}
		case ExhaustionWarning:
			summary.WarningCount++
			if summary.ShortestSecondsToOOM < 0 || pred.SecondsToOOM < summary.ShortestSecondsToOOM {
				summary.ShortestSecondsToOOM = pred.SecondsToOOM
			}
		case ExhaustionModerate:
			summary.ModerateGrowthCount++
		default:
			summary.StableCount++
		}

		rateMBs := pred.SlopeBytesPerSec / (1024 * 1024)
		if rateMBs > summary.FastestGrowingRateMBs {
			summary.FastestGrowingRateMBs = rateMBs
			summary.FastestGrowingName = pred.ContainerName
		}
	}

	// Sort predictions: critical first, then warning, then moderate, then stable
	sort.Slice(predictions, func(i, j int) bool {
		rank := func(c ExhaustionCategory) int {
			switch c {
			case ExhaustionCritical:
				return 0
			case ExhaustionWarning:
				return 1
			case ExhaustionModerate:
				return 2
			default:
				return 3
			}
		}
		if rank(predictions[i].Category) != rank(predictions[j].Category) {
			return rank(predictions[i].Category) < rank(predictions[j].Category)
		}
		return predictions[i].SecondsToOOM < predictions[j].SecondsToOOM
	})

	d.mu.Lock()
	d.lastSummary = summary
	d.mu.Unlock()

	return predictions, nil
}

// GetPredictions returns the most up-to-date linear regression predictions across all containers.
func (d *Detector) GetPredictions() []TrendPrediction {
	all := d.store.AllSeries()
	predictions := make([]TrendPrediction, 0, len(all))

	for id, series := range all {
		samples := series.Samples()
		name := series.name
		pred := PredictExhaustion(id, name, samples, d.fallbackLimit)
		predictions = append(predictions, pred)
	}

	sort.Slice(predictions, func(i, j int) bool {
		rank := func(c ExhaustionCategory) int {
			switch c {
			case ExhaustionCritical:
				return 0
			case ExhaustionWarning:
				return 1
			case ExhaustionModerate:
				return 2
			default:
				return 3
			}
		}
		if rank(predictions[i].Category) != rank(predictions[j].Category) {
			return rank(predictions[i].Category) < rank(predictions[j].Category)
		}
		return predictions[i].SecondsToOOM < predictions[j].SecondsToOOM
	})

	return predictions
}

// GetSummary returns the latest aggregated summary of anomaly radar states.
func (d *Detector) GetSummary() AnomalySummary {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.lastSummary
}

// Alarms returns the alarm manager reference.
func (d *Detector) Alarms() *AlarmManager {
	return d.alarms
}

// Store returns the underlying time-series tracker store.
func (d *Detector) Store() *TrackerStore {
	return d.store
}
