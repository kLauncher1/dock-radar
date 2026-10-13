package security

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	// ErrUnauthorizedOrigin denotes non-loopback requests or cross-origin CSRF attempts.
	ErrUnauthorizedOrigin = errors.New("unauthorized request origin: access restricted to local loopback interface")
	// ErrRateLimitExceeded denotes too many requests within the evaluation window.
	ErrRateLimitExceeded = errors.New("rate limit exceeded: too many container lifecycle operations")
)

// RateLimiter manages thread-safe token bucket rate limiting.
type RateLimiter struct {
	mu         sync.Mutex
	capacity   float64
	tokens     float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

// NewRateLimiter initializes a token bucket limiter.
// capacity: maximum tokens burst; refillPerSec: refill speed in tokens/sec.
func NewRateLimiter(capacity float64, refillPerSec float64) *RateLimiter {
	return &RateLimiter{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillPerSec,
		lastRefill: time.Now(),
	}
}

// Allow attempts to consume 1 token. Returns true if allowed, false if rate limited.
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	rl.lastRefill = now

	// Refill tokens
	rl.tokens += elapsed * rl.refillRate
	if rl.tokens > rl.capacity {
		rl.tokens = rl.capacity
	}

	if rl.tokens >= 1.0 {
		rl.tokens -= 1.0
		return true
	}

	return false
}

// IsLoopbackHost checks whether a host string is a valid local loopback address.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]" {
		return true
	}
	ip := net.ParseIP(h)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// ValidateLoopbackOrigin enforces local-only invocation and anti-CSRF headers.
func ValidateLoopbackOrigin(r *http.Request) error {
	// 1. Allow override if explicitly configured
	if os.Getenv("DOCK_RADAR_ALLOW_REMOTE") == "true" {
		return nil
	}

	// 2. Validate remote IP is loopback
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	if !IsLoopbackHost(remoteHost) {
		return ErrUnauthorizedOrigin
	}

	// 3. Inspect Sec-Fetch-Site if provided by modern browsers
	secFetchSite := r.Header.Get("Sec-Fetch-Site")
	if secFetchSite != "" && secFetchSite == "cross-site" {
		return ErrUnauthorizedOrigin
	}

	// 4. Validate Origin / Referer header if present on mutating requests
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
		originHeader := r.Header.Get("Origin")
		if originHeader != "" {
			u, err := url.Parse(originHeader)
			if err != nil || !IsLoopbackHost(u.Hostname()) {
				return ErrUnauthorizedOrigin
			}
		}

		refererHeader := r.Header.Get("Referer")
		if refererHeader != "" {
			u, err := url.Parse(refererHeader)
			if err != nil || !IsLoopbackHost(u.Hostname()) {
				return ErrUnauthorizedOrigin
			}
		}
	}

	return nil
}
