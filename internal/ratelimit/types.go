package ratelimit

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Algorithm defines the rate limiting mathematical model.
type Algorithm string

const (
	AlgorithmTokenBucket   Algorithm = "token_bucket"
	AlgorithmSlidingWindow Algorithm = "sliding_window"
)

// Scope defines the subject of the rate limit.
type Scope string

const (
	ScopeGlobal    Scope = "global"
	ScopeTenant    Scope = "tenant"
	ScopeIP        Scope = "ip"
)

var validTenantIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)

// TenantQuota defines rate limits and quotas for an individual tenant.
type TenantQuota struct {
	TenantID          string            `json:"tenant_id"`
	Name              string            `json:"name"`
	Tier              string            `json:"tier"` // Free, Standard, Enterprise
	RequestsPerSecond float64           `json:"requests_per_second"`
	BurstCapacity     int               `json:"burst_capacity"`
	WindowSeconds     int               `json:"window_seconds"`
	MaxBytesPerSecond int64             `json:"max_bytes_per_second"` // Bandwidth throttling limit (0 for unlimited)
	Labels            map[string]string `json:"labels,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// Validate checks TenantQuota fields for correctness.
func (q *TenantQuota) Validate() error {
	if q == nil {
		return errors.New("tenant quota cannot be nil")
	}
	q.TenantID = strings.TrimSpace(q.TenantID)
	if q.TenantID == "" {
		return errors.New("tenant_id is required")
	}
	if len(q.TenantID) > 64 {
		return errors.New("tenant_id exceeds maximum length of 64 characters")
	}
	if !validTenantIDRegex.MatchString(q.TenantID) {
		return fmt.Errorf("tenant_id '%s' contains invalid characters (alphanumeric, dashes, underscores only)", q.TenantID)
	}
	if q.RequestsPerSecond <= 0 {
		return errors.New("requests_per_second must be greater than zero")
	}
	if q.RequestsPerSecond > 1000000 {
		return errors.New("requests_per_second cannot exceed 1,000,000")
	}
	if q.BurstCapacity <= 0 {
		return errors.New("burst_capacity must be greater than zero")
	}
	if q.BurstCapacity > 10000000 {
		return errors.New("burst_capacity cannot exceed 10,000,000")
	}
	if q.WindowSeconds <= 0 {
		q.WindowSeconds = 60
	}
	if q.WindowSeconds > 86400 {
		return errors.New("window_seconds cannot exceed 86400 (24h)")
	}
	if q.MaxBytesPerSecond < 0 {
		return errors.New("max_bytes_per_second cannot be negative")
	}
	if q.Tier == "" {
		q.Tier = "Standard"
	}
	return nil
}

// QuotaUsage represents real-time consumption telemetry for a tenant.
type QuotaUsage struct {
	TenantID          string    `json:"tenant_id"`
	CurrentRPS        float64   `json:"current_rps"`
	UsedTokens        float64   `json:"used_tokens"`
	RemainingTokens   float64   `json:"remaining_tokens"`
	BytesInWindow     int64     `json:"bytes_in_window"`
	ThrottledRequests int64     `json:"throttled_requests"`
	TotalRequests     int64     `json:"total_requests"`
	ResetTime         time.Time `json:"reset_time"`
}

// IPBanRecord stores an active or historical IP ban.
type IPBanRecord struct {
	IP             string    `json:"ip"`
	Reason         string    `json:"reason"`
	ViolationCount int       `json:"violation_count"`
	BannedAt       time.Time `json:"banned_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	OriginNode     string    `json:"origin_node"`
	Active         bool      `json:"active"`
}

// Validate checks IPBanRecord fields.
func (b *IPBanRecord) Validate() error {
	if b == nil {
		return errors.New("ip ban record cannot be nil")
	}
	b.IP = strings.TrimSpace(b.IP)
	parsedIP := net.ParseIP(b.IP)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address format: %s", b.IP)
	}
	if parsedIP.IsLoopback() {
		return errors.New("loopback IP addresses cannot be banned")
	}
	if b.Reason == "" {
		b.Reason = "abusive traffic threshold exceeded"
	}
	if len(b.Reason) > 256 {
		b.Reason = b.Reason[:256]
	}
	if b.OriginNode == "" {
		b.OriginNode = "local"
	}
	return nil
}

// LimiterConfig specifies engine configuration.
type LimiterConfig struct {
	Enabled                bool    `json:"enabled"`
	DefaultRPS             float64 `json:"default_rps"`
	DefaultBurst           int     `json:"default_burst"`
	DefaultWindowSec       int     `json:"default_window_sec"`
	DefaultMaxBytesPerSec  int64   `json:"default_max_bytes_per_sec"`
	AutoBanEnabled         bool    `json:"auto_ban_enabled"`
	BanThresholdViolations int     `json:"ban_threshold_violations"`
	BanDurationSeconds     int     `json:"ban_duration_seconds"`
	SyncIntervalSeconds    int     `json:"sync_interval_seconds"`
	SyncSecret             string  `json:"sync_secret,omitempty"`
}

// DefaultLimiterConfig returns production-ready defaults.
func DefaultLimiterConfig() LimiterConfig {
	return LimiterConfig{
		Enabled:                true,
		DefaultRPS:             50.0,
		DefaultBurst:           100,
		DefaultWindowSec:       60,
		DefaultMaxBytesPerSec:  0, // Unlimited by default
		AutoBanEnabled:         true,
		BanThresholdViolations: 10,
		BanDurationSeconds:     900, // 15 minutes
		SyncIntervalSeconds:    15,
		SyncSecret:             "",
	}
}

// Validate ensures configuration invariants are met.
func (c *LimiterConfig) Validate() error {
	if c.DefaultRPS <= 0 {
		c.DefaultRPS = 50.0
	}
	if c.DefaultBurst <= 0 {
		c.DefaultBurst = 100
	}
	if c.DefaultWindowSec <= 0 {
		c.DefaultWindowSec = 60
	}
	if c.BanThresholdViolations <= 0 {
		c.BanThresholdViolations = 10
	}
	if c.BanDurationSeconds <= 0 {
		c.BanDurationSeconds = 900
	}
	if c.SyncIntervalSeconds <= 0 {
		c.SyncIntervalSeconds = 15
	}
	return nil
}

// Sanitized returns a copy of LimiterConfig with secret key masked.
func (c LimiterConfig) Sanitized() LimiterConfig {
	copyCfg := c
	if copyCfg.SyncSecret != "" {
		copyCfg.SyncSecret = "********"
	}
	return copyCfg
}

// LimiterStatus represents high-level telemetry for status endpoints.
type LimiterStatus struct {
	Enabled                 bool      `json:"enabled"`
	TotalTenants            int       `json:"total_tenants"`
	ActiveBannedIPs         int       `json:"active_banned_ips"`
	TotalEvaluations        int64     `json:"total_evaluations"`
	TotalThrottledRequests  int64     `json:"total_throttled_requests"`
	TotalBannedRejections   int64     `json:"total_banned_rejections"`
	TotalBandwidthThrottled int64     `json:"total_bandwidth_throttled"`
	LastSyncTime            time.Time `json:"last_sync_time"`
	SyncedPeersCount        int       `json:"synced_peers_count"`
	UptimeSeconds           int64     `json:"uptime_seconds"`
}
