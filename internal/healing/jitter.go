package healing

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"time"
)

// CalculateBackoff computes exponential backoff with randomized jitter.
// attempt is 1-indexed (1st attempt, 2nd attempt, etc).
// The algorithm clamps exponential growth to maxSec and applies a symmetric
// jitter percentage based on jitterFactor to desynchronize concurrent restarts.
func CalculateBackoff(attempt int, baseSec, maxSec int, jitterFactor float64) time.Duration {
	if attempt <= 0 {
		attempt = 1
	}
	if baseSec <= 0 {
		baseSec = 1
	}
	if maxSec < baseSec {
		maxSec = baseSec
	}

	// 1. Calculate raw exponential backoff: base * 2^(attempt - 1)
	shift := attempt - 1
	if shift > 30 {
		shift = 30
	}

	multiplier := float64(int64(1) << shift)
	rawBackoff := float64(baseSec) * multiplier
	if rawBackoff > float64(maxSec) {
		rawBackoff = float64(maxSec)
	}

	// 2. Apply random jitter: +/- (jitterFactor * rawBackoff)
	if jitterFactor > 0.0 {
		if jitterFactor > 1.0 {
			jitterFactor = 1.0
		}
		r := cryptoFloat64() // in [0, 1)
		// Map [0, 1) to [-jitterFactor, +jitterFactor]
		delta := (r*2.0 - 1.0) * jitterFactor * rawBackoff
		rawBackoff += delta
	}

	// 3. Minimum clamp: 100ms
	if rawBackoff < 0.1 {
		rawBackoff = 0.1
	}

	return time.Duration(rawBackoff * float64(time.Second))
}

// CalculateDeterministicBackoff computes exact exponential backoff without jitter.
func CalculateDeterministicBackoff(attempt int, baseSec, maxSec int) time.Duration {
	return CalculateBackoff(attempt, baseSec, maxSec, 0.0)
}

// cryptoFloat64 returns a cryptographically random float in [0.0, 1.0) with zero global locks.
func cryptoFloat64() float64 {
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return 0.5
	}
	val := binary.BigEndian.Uint64(b[:])
	return float64(val>>11) / float64(uint64(1)<<53)
}

// FormatDuration formats duration into a human-friendly string with single decimal precision.
func FormatDuration(d time.Duration) string {
	sec := d.Seconds()
	if sec < 1.0 {
		if math.Round(sec*1000)/1000 > 0 {
			return d.Round(time.Millisecond).String()
		}
		return "0s"
	}
	return d.Round(100 * time.Millisecond).String()
}
