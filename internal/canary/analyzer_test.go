package canary

import (
	"testing"
	"time"
)

func TestTargetMetricsBuffer_Summary(t *testing.T) {
	buf := NewTargetMetricsBuffer()

	// 100 samples, 5 errors, varied latencies
	for i := 1; i <= 100; i++ {
		isErr := (i <= 5)
		status := 200
		if isErr {
			status = 500
		}
		buf.Add(RequestMetric{
			Target:     "baseline",
			StatusCode: status,
			Duration:   time.Duration(i) * time.Millisecond,
			IsError:    isErr,
		})
	}

	count, errRate, p95 := buf.Summary()
	if count != 100 {
		t.Fatalf("expected count 100, got %d", count)
	}
	if errRate != 5.0 {
		t.Fatalf("expected error rate 5.0%%, got %.2f%%", errRate)
	}
	// 95th percentile of 1..100 is 95ms
	if p95 < 94.0 || p95 > 96.0 {
		t.Fatalf("expected p95 near 95.0ms, got %.2fms", p95)
	}
}

func TestDivergenceAnalyzer_HealthyMetrics(t *testing.T) {
	policy := RollbackPolicy{
		AutoRollback:          true,
		MaxErrorRateDelta:     5.0,
		MaxLatencyP95Ratio:    1.5,
		MinSampleSize:         20,
		ConsecutiveViolations: 1,
	}

	da := NewDivergenceAnalyzer("dep-healthy", policy)

	// Baseline: 50 requests, 1 error (2%), 10ms
	for i := 0; i < 50; i++ {
		da.RecordMetric(RequestMetric{
			Target:     "baseline",
			StatusCode: 200,
			Duration:   10 * time.Millisecond,
		})
	}

	// Canary: 50 requests, 1 error (2%), 11ms
	for i := 0; i < 50; i++ {
		da.RecordMetric(RequestMetric{
			Target:     "canary",
			StatusCode: 200,
			Duration:   11 * time.Millisecond,
		})
	}

	report := da.Evaluate()
	if report.Diverged {
		t.Fatalf("expected healthy canary to not diverge, got trip reason: %s", report.TripReason)
	}
	if report.HealthScore < 90 {
		t.Fatalf("expected high health score, got %d", report.HealthScore)
	}
}

func TestDivergenceAnalyzer_ErrorRateDivergence(t *testing.T) {
	policy := RollbackPolicy{
		AutoRollback:          true,
		MaxErrorRateDelta:     5.0, // Canary must not exceed baseline by > 5%
		MaxLatencyP95Ratio:    2.0,
		MinSampleSize:         20,
		ConsecutiveViolations: 1,
	}

	da := NewDivergenceAnalyzer("dep-err-trip", policy)

	// Baseline: 50 requests, 0 errors (0%)
	for i := 0; i < 50; i++ {
		da.RecordMetric(RequestMetric{
			Target:     "baseline",
			StatusCode: 200,
			Duration:   10 * time.Millisecond,
		})
	}

	// Canary: 50 requests, 10 errors (20%) -> Delta is +20%, exceeding 5%
	for i := 0; i < 50; i++ {
		status := 200
		isErr := false
		if i < 10 {
			status = 503
			isErr = true
		}
		da.RecordMetric(RequestMetric{
			Target:     "canary",
			StatusCode: status,
			Duration:   10 * time.Millisecond,
			IsError:    isErr,
		})
	}

	report := da.Evaluate()
	if !report.Diverged {
		t.Fatalf("expected divergence due to high canary error rate")
	}
	if report.ErrorRateDelta < 19.0 {
		t.Fatalf("expected error rate delta near 20%%, got %.2f%%", report.ErrorRateDelta)
	}
}

func TestDivergenceAnalyzer_LatencyDivergenceAndConsecutive(t *testing.T) {
	policy := RollbackPolicy{
		AutoRollback:          true,
		MaxErrorRateDelta:     5.0,
		MaxLatencyP95Ratio:    1.5, // Canary p95 must not exceed 1.5x baseline
		MinSampleSize:         20,
		ConsecutiveViolations: 2,   // Requires 2 consecutive violations
	}

	da := NewDivergenceAnalyzer("dep-lat-trip", policy)

	// Baseline: 30 requests, 10ms
	for i := 0; i < 30; i++ {
		da.RecordMetric(RequestMetric{
			Target:     "baseline",
			StatusCode: 200,
			Duration:   10 * time.Millisecond,
		})
	}

	// Canary: 30 requests, 30ms (3.0x ratio, > 1.5x threshold)
	for i := 0; i < 30; i++ {
		da.RecordMetric(RequestMetric{
			Target:     "canary",
			StatusCode: 200,
			Duration:   30 * time.Millisecond,
		})
	}

	// First evaluation: Warning state (1/2 consecutive)
	rep1 := da.Evaluate()
	if rep1.Diverged {
		t.Fatalf("expected first violation to NOT trip immediately when ConsecutiveViolations=2")
	}

	// Second evaluation: Diverged state (2/2 consecutive)
	rep2 := da.Evaluate()
	if !rep2.Diverged {
		t.Fatalf("expected second violation to trip divergence")
	}
	if rep2.LatencyP95Ratio < 2.5 {
		t.Fatalf("expected latency ratio near 3.0x, got %.2fx", rep2.LatencyP95Ratio)
	}
}

func TestDivergenceAnalyzer_WarmupGuard(t *testing.T) {
	policy := RollbackPolicy{
		AutoRollback:          true,
		MaxErrorRateDelta:     5.0,
		MaxLatencyP95Ratio:    1.5,
		MinSampleSize:         50,
		ConsecutiveViolations: 1,
	}

	da := NewDivergenceAnalyzer("dep-warmup", policy)

	// Ingest only 10 canary samples (below 50 min)
	for i := 0; i < 10; i++ {
		da.RecordMetric(RequestMetric{
			Target:     "canary",
			StatusCode: 500, // 100% errors, but during warmup
			Duration:   50 * time.Millisecond,
			IsError:    true,
		})
	}

	report := da.Evaluate()
	if report.Diverged {
		t.Fatalf("expected warmup guard to prevent premature divergence trip")
	}
}
