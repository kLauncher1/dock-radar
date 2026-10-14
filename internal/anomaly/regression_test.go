package anomaly

import (
	"math"
	"testing"
	"time"
)

func TestCalculateLinearRegression_PerfectLine(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Growth of 1,000,000 bytes per second
	samples := []MetricSample{
		{Timestamp: t0, MemoryBytes: 10000000},
		{Timestamp: t0.Add(1 * time.Second), MemoryBytes: 11000000},
		{Timestamp: t0.Add(2 * time.Second), MemoryBytes: 12000000},
		{Timestamp: t0.Add(3 * time.Second), MemoryBytes: 13000000},
		{Timestamp: t0.Add(4 * time.Second), MemoryBytes: 14000000},
	}

	slope, intercept, r2 := CalculateLinearRegression(samples)

	if math.Abs(slope-1000000.0) > 1e-4 {
		t.Fatalf("expected slope 1,000,000, got %f", slope)
	}
	if math.Abs(intercept-10000000.0) > 1e-4 {
		t.Fatalf("expected intercept 10,000,000, got %f", intercept)
	}
	if math.Abs(r2-1.0) > 1e-4 {
		t.Fatalf("expected R^2 of 1.0, got %f", r2)
	}
}

func TestCalculateLinearRegression_FlatLine(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	samples := []MetricSample{
		{Timestamp: t0, MemoryBytes: 50000000},
		{Timestamp: t0.Add(1 * time.Second), MemoryBytes: 50000000},
		{Timestamp: t0.Add(2 * time.Second), MemoryBytes: 50000000},
	}

	slope, _, r2 := CalculateLinearRegression(samples)
	if math.Abs(slope) > 1e-6 {
		t.Fatalf("expected 0 slope for flat metrics, got %f", slope)
	}
	if r2 != 1.0 {
		t.Fatalf("expected R^2 1.0 for flat metrics, got %f", r2)
	}
}

func TestPredictExhaustion_CriticalImminent(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Memory limit: 100 MB (104,857,600 bytes)
	// Growth: 1 MB/s (1,048,576 B/s)
	// Current at t=4s: 90 MB (94,371,840 bytes)
	// Remaining: 10 MB -> ~10 seconds to OOM!
	limit := uint64(104857600)
	samples := []MetricSample{
		{Timestamp: t0, MemoryBytes: 90177536, MemoryLimit: limit},
		{Timestamp: t0.Add(1 * time.Second), MemoryBytes: 91226112, MemoryLimit: limit},
		{Timestamp: t0.Add(2 * time.Second), MemoryBytes: 92274688, MemoryLimit: limit},
		{Timestamp: t0.Add(3 * time.Second), MemoryBytes: 93323264, MemoryLimit: limit},
		{Timestamp: t0.Add(4 * time.Second), MemoryBytes: 94371840, MemoryLimit: limit},
	}

	pred := PredictExhaustion("test-container", "worker", samples, 0)

	if pred.Category != ExhaustionCritical {
		t.Fatalf("expected Category %s, got %s", ExhaustionCritical, pred.Category)
	}
	if pred.SecondsToOOM < 9.0 || pred.SecondsToOOM > 11.0 {
		t.Fatalf("expected ~10s to OOM, got %f", pred.SecondsToOOM)
	}
	if pred.Confidence != "medium" { // 5 samples
		t.Fatalf("expected confidence medium, got %s", pred.Confidence)
	}
}

func TestPredictExhaustion_WarningHorizon(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Memory limit: 100 MB
	// Current at t=4s: 50 MB
	// Slope: 250 KB/s (256,000 bytes/sec)
	// Remaining: 50 MB -> 52,428,800 / 256,000 = ~204.8 seconds (~3.4 minutes) -> Warning!
	limit := uint64(104857600)
	samples := []MetricSample{
		{Timestamp: t0, MemoryBytes: 51404800, MemoryLimit: limit},
		{Timestamp: t0.Add(1 * time.Second), MemoryBytes: 51660800, MemoryLimit: limit},
		{Timestamp: t0.Add(2 * time.Second), MemoryBytes: 51916800, MemoryLimit: limit},
		{Timestamp: t0.Add(3 * time.Second), MemoryBytes: 52172800, MemoryLimit: limit},
		{Timestamp: t0.Add(4 * time.Second), MemoryBytes: 52428800, MemoryLimit: limit},
	}

	pred := PredictExhaustion("test-container", "worker", samples, 0)
	if pred.Category != ExhaustionWarning {
		t.Fatalf("expected Category %s, got %s", ExhaustionWarning, pred.Category)
	}
	if pred.SecondsToOOM < 200.0 || pred.SecondsToOOM > 210.0 {
		t.Fatalf("expected ~204s to OOM, got %f", pred.SecondsToOOM)
	}
}

func TestPredictExhaustion_StableNegativeGrowth(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Shrinking memory (garbage collector freed memory)
	limit := uint64(104857600)
	samples := []MetricSample{
		{Timestamp: t0, MemoryBytes: 60000000, MemoryLimit: limit},
		{Timestamp: t0.Add(1 * time.Second), MemoryBytes: 55000000, MemoryLimit: limit},
		{Timestamp: t0.Add(2 * time.Second), MemoryBytes: 50000000, MemoryLimit: limit},
	}

	pred := PredictExhaustion("test-container", "worker", samples, 0)
	if pred.Category != ExhaustionStable {
		t.Fatalf("expected Category %s, got %s", ExhaustionStable, pred.Category)
	}
	if pred.SecondsToOOM != -1.0 {
		t.Fatalf("expected SecondsToOOM -1 for shrinking memory, got %f", pred.SecondsToOOM)
	}
}
