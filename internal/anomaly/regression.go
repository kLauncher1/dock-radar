package anomaly

import (
	"math"
	"time"
)

// ExhaustionCategory classifies the operational risk of out-of-memory kernel termination.
type ExhaustionCategory string

const (
	ExhaustionStable    ExhaustionCategory = "stable"
	ExhaustionModerate  ExhaustionCategory = "moderate_growth"
	ExhaustionWarning   ExhaustionCategory = "warning"
	ExhaustionCritical  ExhaustionCategory = "critical_oom_imminent"
)

// TrendPrediction models linear regression forecasting of memory consumption and OOM risk.
type TrendPrediction struct {
	ContainerID        string             `json:"container_id"`
	ContainerName      string             `json:"container_name"`
	SampleCount        int                `json:"sample_count"`
	CurrentMemoryBytes uint64             `json:"current_memory_bytes"`
	MemoryLimitBytes   uint64             `json:"memory_limit_bytes"`
	MemoryUsagePercent float64            `json:"memory_usage_percent"`
	SlopeBytesPerSec   float64            `json:"slope_bytes_per_sec"`
	Intercept          float64            `json:"intercept"`
	RSquared           float64            `json:"r_squared"`
	SecondsToOOM       float64            `json:"seconds_to_oom"`
	Category           ExhaustionCategory `json:"category"`
	Confidence         string             `json:"confidence"`
	GeneratedAt        time.Time          `json:"generated_at"`
}

// CalculateLinearRegression performs Ordinary Least Squares (OLS) regression on time-series samples.
func CalculateLinearRegression(samples []MetricSample) (slope, intercept, rSquared float64) {
	n := len(samples)
	if n < 2 {
		return 0.0, 0.0, 0.0
	}

	t0 := samples[0].Timestamp
	tValues := make([]float64, n)
	yValues := make([]float64, n)

	var sumT, sumY float64
	for i, s := range samples {
		dt := s.Timestamp.Sub(t0).Seconds()
		y := float64(s.MemoryBytes)
		tValues[i] = dt
		yValues[i] = y
		sumT += dt
		sumY += y
	}

	meanT := sumT / float64(n)
	meanY := sumY / float64(n)

	var num, denT, denY float64
	for i := 0; i < n; i++ {
		tDiff := tValues[i] - meanT
		yDiff := yValues[i] - meanY
		num += tDiff * yDiff
		denT += tDiff * tDiff
		denY += yDiff * yDiff
	}

	if denT <= 1e-9 {
		// Zero elapsed time between measurements
		return 0.0, meanY, 0.0
	}

	slope = num / denT
	intercept = meanY - slope*meanT

	if denY <= 1e-9 {
		// Constant memory usage across all samples (perfect fit with 0 slope)
		if math.Abs(slope) < 1e-6 {
			return 0.0, meanY, 1.0
		}
		return slope, intercept, 0.0
	}

	// Calculate coefficient of determination (R^2)
	var ssRes float64
	for i := 0; i < n; i++ {
		predicted := slope*tValues[i] + intercept
		residual := yValues[i] - predicted
		ssRes += residual * residual
	}

	r2 := 1.0 - (ssRes / denY)
	if math.IsNaN(r2) || r2 < 0.0 {
		r2 = 0.0
	} else if r2 > 1.0 {
		r2 = 1.0
	}

	return slope, intercept, r2
}

// PredictExhaustion models time until container memory limit is breached based on regression slope.
func PredictExhaustion(id, name string, samples []MetricSample, fallbackLimit uint64) TrendPrediction {
	now := time.Now().UTC()
	pred := TrendPrediction{
		ContainerID:   id,
		ContainerName: name,
		SampleCount:   len(samples),
		Category:      ExhaustionStable,
		Confidence:    "insufficient_data",
		SecondsToOOM:  -1.0,
		GeneratedAt:   now,
	}

	if len(samples) < 3 {
		if len(samples) > 0 {
			last := samples[len(samples)-1]
			pred.CurrentMemoryBytes = last.MemoryBytes
			pred.MemoryLimitBytes = last.MemoryLimit
			if pred.MemoryLimitBytes == 0 {
				pred.MemoryLimitBytes = fallbackLimit
			}
			if pred.MemoryLimitBytes > 0 {
				pred.MemoryUsagePercent = (float64(pred.CurrentMemoryBytes) / float64(pred.MemoryLimitBytes)) * 100.0
			}
		}
		return pred
	}

	last := samples[len(samples)-1]
	pred.CurrentMemoryBytes = last.MemoryBytes
	limit := last.MemoryLimit
	if limit == 0 {
		limit = fallbackLimit
	}
	if limit == 0 {
		limit = 1024 * 1024 * 1024 // 1 GB fallback if neither container nor host limit is configured
	}
	pred.MemoryLimitBytes = limit

	if limit > 0 {
		pred.MemoryUsagePercent = (float64(pred.CurrentMemoryBytes) / float64(limit)) * 100.0
	}

	slope, intercept, r2 := CalculateLinearRegression(samples)
	pred.SlopeBytesPerSec = slope
	pred.Intercept = intercept
	pred.RSquared = r2

	// Determine confidence level
	if len(samples) >= 10 && r2 >= 0.75 {
		pred.Confidence = "high"
	} else if len(samples) >= 5 && r2 >= 0.45 {
		pred.Confidence = "medium"
	} else {
		pred.Confidence = "low"
	}

	// If memory slope is non-positive or negligible (< 1024 bytes/sec growth)
	if slope <= 1024.0 {
		pred.SecondsToOOM = -1.0
		if pred.MemoryUsagePercent >= 95.0 {
			pred.Category = ExhaustionWarning
		} else {
			pred.Category = ExhaustionStable
		}
		return pred
	}

	// Memory is climbing with positive slope
	if pred.CurrentMemoryBytes >= limit {
		pred.SecondsToOOM = 0.0
		pred.Category = ExhaustionCritical
		return pred
	}

	remainingBytes := float64(limit - pred.CurrentMemoryBytes)
	secondsRemaining := remainingBytes / slope
	pred.SecondsToOOM = math.Round(secondsRemaining*100) / 100

	// Risk classification matrix
	if secondsRemaining <= 60.0 || (pred.MemoryUsagePercent >= 92.0 && secondsRemaining <= 180.0) {
		pred.Category = ExhaustionCritical
	} else if secondsRemaining <= 300.0 || (pred.MemoryUsagePercent >= 82.0 && secondsRemaining <= 600.0) {
		pred.Category = ExhaustionWarning
	} else if secondsRemaining <= 1800.0 {
		pred.Category = ExhaustionModerate
	} else {
		pred.Category = ExhaustionStable
	}

	return pred
}
