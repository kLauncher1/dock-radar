package canary

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

const maxMetricsPerTarget = 1000

// TargetMetricsBuffer maintains an in-memory rolling sample window for a specific target.
type TargetMetricsBuffer struct {
	samples []RequestMetric
	mu      sync.RWMutex
}

// NewTargetMetricsBuffer creates a bounded buffer for request telemetry.
func NewTargetMetricsBuffer() *TargetMetricsBuffer {
	return &TargetMetricsBuffer{
		samples: make([]RequestMetric, 0, maxMetricsPerTarget),
	}
}

// Add appends a metric sample and evicts oldest items if capacity exceeded.
func (b *TargetMetricsBuffer) Add(m RequestMetric) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.samples) >= maxMetricsPerTarget {
		// Evict oldest 20%
		evictCount := maxMetricsPerTarget / 5
		copy(b.samples, b.samples[evictCount:])
		b.samples = b.samples[:len(b.samples)-evictCount]
	}
	b.samples = append(b.samples, m)
}

// Summary calculates count, error rate, and p95 latency.
func (b *TargetMetricsBuffer) Summary() (count int, errRate float64, p95Ms float64) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	n := len(b.samples)
	if n == 0 {
		return 0, 0.0, 0.0
	}

	errCount := 0
	latencies := make([]float64, n)

	for i, s := range b.samples {
		if s.IsError || s.StatusCode >= 500 {
			errCount++
		}
		latencies[i] = float64(s.Duration.Microseconds()) / 1000.0 // Milliseconds
	}

	errRate = (float64(errCount) / float64(n)) * 100.0

	sort.Float64s(latencies)
	p95Idx := int(math.Ceil(0.95*float64(n))) - 1
	if p95Idx < 0 {
		p95Idx = 0
	} else if p95Idx >= n {
		p95Idx = n - 1
	}
	p95Ms = latencies[p95Idx]

	return n, errRate, p95Ms
}

// Reset clears the buffer.
func (b *TargetMetricsBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.samples = b.samples[:0]
}

// DivergenceAnalyzer monitors real-time telemetry and flags anomalies violating rollback criteria.
type DivergenceAnalyzer struct {
	deploymentID          string
	baseline              *TargetMetricsBuffer
	canary                *TargetMetricsBuffer
	shadow                *TargetMetricsBuffer
	policy                RollbackPolicy
	consecutiveViolations int
	mu                    sync.RWMutex
}

// NewDivergenceAnalyzer constructs an analyzer for a specific canary deployment.
func NewDivergenceAnalyzer(deploymentID string, policy RollbackPolicy) *DivergenceAnalyzer {
	return &DivergenceAnalyzer{
		deploymentID: deploymentID,
		baseline:     NewTargetMetricsBuffer(),
		canary:       NewTargetMetricsBuffer(),
		shadow:       NewTargetMetricsBuffer(),
		policy:       policy,
	}
}

// RecordMetric ingests a single request sample into the appropriate target buffer.
func (da *DivergenceAnalyzer) RecordMetric(m RequestMetric) {
	switch m.Target {
	case "baseline":
		da.baseline.Add(m)
	case "canary":
		da.canary.Add(m)
	case "shadow":
		da.shadow.Add(m)
	}
}

// Evaluate performs comparative divergence analysis between baseline and canary telemetry.
func (da *DivergenceAnalyzer) Evaluate() CanaryDivergenceReport {
	da.mu.Lock()
	defer da.mu.Unlock()

	baseN, baseErrRate, baseP95 := da.baseline.Summary()
	canN, canErrRate, canP95 := da.canary.Summary()
	shadN, _, _ := da.shadow.Summary()

	report := CanaryDivergenceReport{
		DeploymentID:         da.deploymentID,
		EvaluatedAt:          time.Now().UTC(),
		BaselineSamples:      baseN,
		CanarySamples:        canN,
		ShadowSamples:        shadN,
		BaselineErrorRate:    math.Round(baseErrRate*100) / 100,
		CanaryErrorRate:      math.Round(canErrRate*100) / 100,
		ErrorRateDelta:       math.Round((canErrRate-baseErrRate)*100) / 100,
		BaselineP95LatencyMs: math.Round(baseP95*100) / 100,
		CanaryP95LatencyMs:   math.Round(canP95*100) / 100,
	}

	// Calculate Latency Ratio
	if baseP95 > 0.001 {
		report.LatencyP95Ratio = math.Round((canP95/baseP95)*100) / 100
	} else if canP95 > 0.001 {
		report.LatencyP95Ratio = 2.0 // Arbitrary threshold if baseline had near-zero latency
	} else {
		report.LatencyP95Ratio = 1.0
	}

	// Calculate Health Score (100 is perfect)
	health := 100.0
	if report.ErrorRateDelta > 0 {
		health -= math.Min(50.0, report.ErrorRateDelta*5.0)
	}
	if report.LatencyP95Ratio > 1.0 {
		health -= math.Min(50.0, (report.LatencyP95Ratio-1.0)*30.0)
	}
	if health < 0 {
		health = 0
	}
	report.HealthScore = int(math.Round(health))

	// Insufficient sample check
	minSamples := da.policy.MinSampleSize
	if minSamples <= 0 {
		minSamples = 20
	}

	if canN < minSamples {
		report.Diverged = false
		report.TripReason = fmt.Sprintf("sample size warmup (%d/%d required)", canN, minSamples)
		da.consecutiveViolations = 0
		return report
	}

	// Divergence checks
	var tripReasons []string

	// 1. Error rate divergence
	if da.policy.MaxErrorRateDelta > 0 && report.ErrorRateDelta > da.policy.MaxErrorRateDelta {
		tripReasons = append(tripReasons, fmt.Sprintf("error rate delta +%.2f%% exceeded threshold %.2f%%", report.ErrorRateDelta, da.policy.MaxErrorRateDelta))
	}

	// 2. Latency divergence
	if da.policy.MaxLatencyP95Ratio > 0 && report.LatencyP95Ratio > da.policy.MaxLatencyP95Ratio {
		tripReasons = append(tripReasons, fmt.Sprintf("p95 latency ratio %.2fx exceeded threshold %.2fx (%.2fms vs %.2fms)", report.LatencyP95Ratio, da.policy.MaxLatencyP95Ratio, canP95, baseP95))
	}

	consecutiveReq := da.policy.ConsecutiveViolations
	if consecutiveReq <= 0 {
		consecutiveReq = 1
	}

	if len(tripReasons) > 0 {
		da.consecutiveViolations++
		if da.consecutiveViolations >= consecutiveReq {
			report.Diverged = true
			report.TripReason = fmt.Sprintf("anomaly divergence tripped (%d/%d consecutive): %s", da.consecutiveViolations, consecutiveReq, formatReasons(tripReasons))
		} else {
			report.Diverged = false
			report.TripReason = fmt.Sprintf("pre-divergence warning (%d/%d consecutive): %s", da.consecutiveViolations, consecutiveReq, formatReasons(tripReasons))
		}
	} else {
		da.consecutiveViolations = 0
		report.Diverged = false
	}

	return report
}

func formatReasons(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	res := reasons[0]
	for i := 1; i < len(reasons); i++ {
		res += "; " + reasons[i]
	}
	return res
}

// UpdatePolicy updates the rollback policy dynamically.
func (da *DivergenceAnalyzer) UpdatePolicy(p RollbackPolicy) {
	da.mu.Lock()
	defer da.mu.Unlock()
	da.policy = p
}

// ResetBuffers flushes all collected metrics.
func (da *DivergenceAnalyzer) ResetBuffers() {
	da.baseline.Reset()
	da.canary.Reset()
	da.shadow.Reset()
	da.mu.Lock()
	da.consecutiveViolations = 0
	da.mu.Unlock()
}
