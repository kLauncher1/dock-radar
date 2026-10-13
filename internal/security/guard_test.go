package security

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host   string
		expect bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"[::1]", true},
		{"192.168.1.100", false},
		{"10.0.0.1", false},
		{"attacker.com", false},
		{"", false},
	}

	for _, c := range cases {
		got := IsLoopbackHost(c.host)
		if got != c.expect {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", c.host, got, c.expect)
		}
	}
}

func TestValidateLoopbackOrigin(t *testing.T) {
	_ = os.Unsetenv("DOCK_RADAR_ALLOW_REMOTE")

	// 1. Valid local request
	req := httptest.NewRequest(http.MethodPost, "/api/docker/restart", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("Origin", "http://localhost:9080")
	if err := ValidateLoopbackOrigin(req); err != nil {
		t.Fatalf("expected valid loopback request to succeed, got %v", err)
	}

	// 2. Remote address rejected
	reqRemote := httptest.NewRequest(http.MethodPost, "/api/docker/restart", nil)
	reqRemote.RemoteAddr = "192.168.1.50:54321"
	if err := ValidateLoopbackOrigin(reqRemote); !errors.Is(err, ErrUnauthorizedOrigin) {
		t.Fatalf("expected ErrUnauthorizedOrigin for remote IP, got %v", err)
	}

	// 3. Sec-Fetch-Site cross-site rejected
	reqCrossSite := httptest.NewRequest(http.MethodPost, "/api/docker/restart", nil)
	reqCrossSite.RemoteAddr = "127.0.0.1:54321"
	reqCrossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	if err := ValidateLoopbackOrigin(reqCrossSite); !errors.Is(err, ErrUnauthorizedOrigin) {
		t.Fatalf("expected ErrUnauthorizedOrigin for cross-site, got %v", err)
	}

	// 4. Remote Origin header rejected
	reqBadOrigin := httptest.NewRequest(http.MethodPost, "/api/docker/restart", nil)
	reqBadOrigin.RemoteAddr = "127.0.0.1:54321"
	reqBadOrigin.Header.Set("Origin", "https://malicious-site.com")
	if err := ValidateLoopbackOrigin(reqBadOrigin); !errors.Is(err, ErrUnauthorizedOrigin) {
		t.Fatalf("expected ErrUnauthorizedOrigin for bad origin, got %v", err)
	}

	// 5. Remote allowed when override environment variable is set
	_ = os.Setenv("DOCK_RADAR_ALLOW_REMOTE", "true")
	defer os.Unsetenv("DOCK_RADAR_ALLOW_REMOTE")
	if err := ValidateLoopbackOrigin(reqRemote); err != nil {
		t.Fatalf("expected override to allow remote, got %v", err)
	}
}

func TestRateLimiter(t *testing.T) {
	// Limiter with capacity 2, refill rate 10 per second
	limiter := NewRateLimiter(2.0, 10.0)

	// Consume 2 tokens
	if !limiter.Allow() {
		t.Fatalf("token 1 should be allowed")
	}
	if !limiter.Allow() {
		t.Fatalf("token 2 should be allowed")
	}

	// 3rd immediate token should be rejected
	if limiter.Allow() {
		t.Fatalf("token 3 should be rejected due to capacity limit")
	}

	// Sleep 150ms -> refills 1.5 tokens
	time.Sleep(150 * time.Millisecond)
	if !limiter.Allow() {
		t.Fatalf("token should be allowed after refill interval")
	}
}
