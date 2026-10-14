package healing

import (
	"testing"
	"time"
)

func TestCalculateDeterministicBackoff(t *testing.T) {
	base := 2
	max := 30

	expected := []struct {
		attempt  int
		expected time.Duration
	}{
		{attempt: 1, expected: 2 * time.Second},   // 2 * 2^0 = 2s
		{attempt: 2, expected: 4 * time.Second},   // 2 * 2^1 = 4s
		{attempt: 3, expected: 8 * time.Second},   // 2 * 2^2 = 8s
		{attempt: 4, expected: 16 * time.Second},  // 2 * 2^3 = 16s
		{attempt: 5, expected: 30 * time.Second},  // capped at max (30s)
		{attempt: 10, expected: 30 * time.Second}, // capped at max (30s)
	}

	for _, tc := range expected {
		actual := CalculateDeterministicBackoff(tc.attempt, base, max)
		if actual != tc.expected {
			t.Errorf("Attempt %d: expected %v, got %v", tc.attempt, tc.expected, actual)
		}
	}
}

func TestCalculateBackoff_JitterBounds(t *testing.T) {
	base := 10
	max := 100
	jitter := 0.2 // +/- 20%

	// For attempt 1: raw = 10s. With 20% jitter, expected range [8.0s, 12.0s]
	minExpected := 8 * time.Second
	maxExpected := 12 * time.Second

	for i := 0; i < 100; i++ {
		val := CalculateBackoff(1, base, max, jitter)
		if val < minExpected || val > maxExpected {
			t.Fatalf("Iteration %d: backoff %v outside expected bounds [%v, %v]", i, val, minExpected, maxExpected)
		}
	}
}

func TestCalculateBackoff_ZeroAndNegativeAttempts(t *testing.T) {
	valZero := CalculateDeterministicBackoff(0, 2, 20)
	valNeg := CalculateDeterministicBackoff(-5, 2, 20)
	valOne := CalculateDeterministicBackoff(1, 2, 20)

	if valZero != valOne || valNeg != valOne {
		t.Errorf("Expected attempt <= 0 to normalize to attempt 1: zero=%v, neg=%v, one=%v", valZero, valNeg, valOne)
	}
}

func TestFormatDuration(t *testing.T) {
	if s := FormatDuration(2500 * time.Millisecond); s != "2.5s" {
		t.Errorf("Expected 2.5s, got %s", s)
	}
	if s := FormatDuration(500 * time.Millisecond); s != "500ms" {
		t.Errorf("Expected 500ms, got %s", s)
	}
}
