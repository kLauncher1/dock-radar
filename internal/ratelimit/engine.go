package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
)

// LimiterEngine orchestrates distributed rate limiting, token buckets,
// sliding-window bandwidth quotas, and peer IP ban synchronization.
type LimiterEngine struct {
	mu                      sync.RWMutex
	config                  LimiterConfig
	nodeID                  string
	globalBucket            *TokenBucket
	tenantBuckets           map[string]*TokenBucket
	tenantWindows           map[string]*SlidingWindowCounter
	tenantBandwidth         map[string]*SlidingWindowCounter
	tenantQuotas            map[string]*TenantQuota
	ipBanStore              *IPBanStore
	totalEvaluations        int64
	totalThrottledRequests  int64
	totalBannedRejections   int64
	totalBandwidthThrottled int64
	syncedPeersCount        int
	lastSyncTime            time.Time
	startTime               time.Time
	alertDispatcher         *alert.Dispatcher
	auditLogger             *audit.Logger
	stopChan                chan struct{}
}

// NewLimiterEngine initializes the master rate limiter coordinator.
func NewLimiterEngine(cfg LimiterConfig, nodeID string, alertDispatcher *alert.Dispatcher, auditLogger *audit.Logger) *LimiterEngine {
	_ = cfg.Validate()
	if nodeID == "" {
		nodeID = "local-node"
	}

	engine := &LimiterEngine{
		config:          cfg,
		nodeID:          nodeID,
		globalBucket:    NewTokenBucket(cfg.DefaultRPS, float64(cfg.DefaultBurst)),
		tenantBuckets:   make(map[string]*TokenBucket),
		tenantWindows:   make(map[string]*SlidingWindowCounter),
		tenantBandwidth: make(map[string]*SlidingWindowCounter),
		tenantQuotas:    make(map[string]*TenantQuota),
		ipBanStore:      NewIPBanStore(cfg.BanThresholdViolations, time.Duration(cfg.BanDurationSeconds)*time.Second, cfg.AutoBanEnabled),
		startTime:       time.Now(),
		alertDispatcher: alertDispatcher,
		auditLogger:     auditLogger,
		stopChan:        make(chan struct{}),
	}

	return engine
}

// Start begins background maintenance routines (periodic sweeps of expired bans).
func (e *LimiterEngine) Start(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-e.stopChan:
				return
			case <-ticker.C:
				e.ipBanStore.SweepExpired()
			}
		}
	}()
}

// Stop cleanly stops the background goroutines.
func (e *LimiterEngine) Stop() {
	select {
	case <-e.stopChan:
		// already closed
	default:
		close(e.stopChan)
	}
}

// CheckRequest evaluates whether an incoming request from a tenant and client IP is allowed.
// Returns (allowed, failureReason, retryAfter).
func (e *LimiterEngine) CheckRequest(tenantID string, clientIP string, cost int, byteCount int64) (bool, string, time.Duration) {
	if !e.config.Enabled {
		return true, "", 0
	}

	atomic.AddInt64(&e.totalEvaluations, 1)

	// 1. IP Ban Verification
	if clientIP != "" {
		if banned, record := e.ipBanStore.IsBanned(clientIP); banned {
			atomic.AddInt64(&e.totalBannedRejections, 1)
			remaining := time.Until(record.ExpiresAt)
			if remaining < time.Second {
				remaining = time.Second
			}
			return false, fmt.Sprintf("Client IP is banned due to abuse (%s)", record.Reason), remaining
		}
	}

	// 2. Global Rate Limit Check
	allowed, retryAfter := e.globalBucket.Allow(float64(cost))
	if !allowed {
		atomic.AddInt64(&e.totalThrottledRequests, 1)
		if clientIP != "" {
			e.RecordViolation(clientIP, "Global rate limit threshold breached")
		}
		return false, "Global rate limit exceeded", retryAfter
	}

	// 3. Tenant-Specific Quota Check
	if tenantID != "" {
		e.mu.Lock()
		quota, exists := e.tenantQuotas[tenantID]
		if !exists {
			// Auto-provision standard tenant quota
			quota = &TenantQuota{
				TenantID:          tenantID,
				Name:              tenantID,
				Tier:              "Standard",
				RequestsPerSecond: e.config.DefaultRPS,
				BurstCapacity:     e.config.DefaultBurst,
				WindowSeconds:     e.config.DefaultWindowSec,
				MaxBytesPerSecond: e.config.DefaultMaxBytesPerSec,
				CreatedAt:         time.Now(),
				UpdatedAt:         time.Now(),
			}
			e.tenantQuotas[tenantID] = quota
		}

		tb, hasTB := e.tenantBuckets[tenantID]
		if !hasTB {
			tb = NewTokenBucket(quota.RequestsPerSecond, float64(quota.BurstCapacity))
			e.tenantBuckets[tenantID] = tb
		}

		sw, hasSW := e.tenantWindows[tenantID]
		if !hasSW {
			sw = NewSlidingWindowCounter(time.Duration(quota.WindowSeconds)*time.Second, time.Second, int64(quota.RequestsPerSecond*float64(quota.WindowSeconds)))
			e.tenantWindows[tenantID] = sw
		}

		bw, hasBW := e.tenantBandwidth[tenantID]
		if !hasBW && quota.MaxBytesPerSecond > 0 {
			bw = NewSlidingWindowCounter(time.Second, 100*time.Millisecond, quota.MaxBytesPerSecond)
			e.tenantBandwidth[tenantID] = bw
		}
		e.mu.Unlock()

		// Evaluate tenant token bucket
		tAllowed, tRetry := tb.Allow(float64(cost))
		if !tAllowed {
			atomic.AddInt64(&e.totalThrottledRequests, 1)
			if clientIP != "" {
				e.RecordViolation(clientIP, fmt.Sprintf("Tenant %s rate limit exceeded", tenantID))
			}
			return false, fmt.Sprintf("Tenant quota exceeded for %s", tenantID), tRetry
		}

		// Record in sliding window counter
		sw.Allow(int64(cost))

		// Check bandwidth quota if enabled
		if byteCount > 0 && quota.MaxBytesPerSecond > 0 && bw != nil {
			bAllowed, _, _ := bw.Allow(byteCount)
			if !bAllowed {
				atomic.AddInt64(&e.totalBandwidthThrottled, 1)
				return false, fmt.Sprintf("Tenant bandwidth throttling active for %s", tenantID), time.Second
			}
		}
	}

	return true, "", 0
}

// RecordViolation registers an abuse violation and dispatches alerts if an IP is banned.
func (e *LimiterEngine) RecordViolation(clientIP string, reason string) {
	banned, record := e.ipBanStore.RecordViolation(clientIP, reason)
	if banned && record != nil {
		if e.auditLogger != nil {
			e.auditLogger.Log(audit.AuditEvent{
				Action:   "ratelimit_ip_ban",
				Target:   clientIP,
				Actor:    "system",
				ClientIP: clientIP,
				Status:   "success",
				Details: map[string]any{
					"reason":   reason,
					"duration": record.ExpiresAt.Sub(record.BannedAt).String(),
				},
			})
		}
		if e.alertDispatcher != nil {
			_ = e.alertDispatcher.Dispatch(context.Background(), alert.Event{
				Timestamp: time.Now(),
				Level:     alert.LevelCritical,
				Source:    "ratelimit",
				EventType: "ip_ban_enacted",
				Message:   fmt.Sprintf("Abuse protection: IP %s has been banned for %v. Reason: %s", clientIP, record.ExpiresAt.Sub(record.BannedAt), reason),
			})
		}
	}
}

// SetTenantQuota creates or updates a tenant quota.
func (e *LimiterEngine) SetTenantQuota(quota TenantQuota) error {
	if err := quota.Validate(); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	existing, exists := e.tenantQuotas[quota.TenantID]
	if exists {
		quota.CreatedAt = existing.CreatedAt
	} else {
		quota.CreatedAt = now
	}
	quota.UpdatedAt = now

	e.tenantQuotas[quota.TenantID] = &quota

	// Update existing buckets if present
	if tb, ok := e.tenantBuckets[quota.TenantID]; ok {
		tb.UpdateConfig(quota.RequestsPerSecond, float64(quota.BurstCapacity))
	} else {
		e.tenantBuckets[quota.TenantID] = NewTokenBucket(quota.RequestsPerSecond, float64(quota.BurstCapacity))
	}

	e.tenantWindows[quota.TenantID] = NewSlidingWindowCounter(
		time.Duration(quota.WindowSeconds)*time.Second,
		time.Second,
		int64(quota.RequestsPerSecond*float64(quota.WindowSeconds)),
	)

	if quota.MaxBytesPerSecond > 0 {
		e.tenantBandwidth[quota.TenantID] = NewSlidingWindowCounter(time.Second, 100*time.Millisecond, quota.MaxBytesPerSecond)
	} else {
		delete(e.tenantBandwidth, quota.TenantID)
	}

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:   "ratelimit_quota_update",
			Target:   quota.TenantID,
			Actor:    "admin",
			ClientIP: "127.0.0.1",
			Status:   "success",
			Details: map[string]any{
				"rps":   quota.RequestsPerSecond,
				"burst": quota.BurstCapacity,
			},
		})
	}

	return nil
}

// DeleteTenantQuota removes a tenant quota configuration.
func (e *LimiterEngine) DeleteTenantQuota(tenantID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.tenantQuotas[tenantID]; exists {
		delete(e.tenantQuotas, tenantID)
		delete(e.tenantBuckets, tenantID)
		delete(e.tenantWindows, tenantID)
		delete(e.tenantBandwidth, tenantID)
		if e.auditLogger != nil {
			e.auditLogger.Log(audit.AuditEvent{
				Action:   "ratelimit_quota_delete",
				Target:   tenantID,
				Actor:    "admin",
				ClientIP: "127.0.0.1",
				Status:   "success",
			})
		}
		return true
	}
	return false
}

// GetTenantQuota returns the quota for a specific tenant.
func (e *LimiterEngine) GetTenantQuota(tenantID string) (*TenantQuota, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	quota, exists := e.tenantQuotas[tenantID]
	if !exists {
		return nil, false
	}
	copyQuota := *quota
	return &copyQuota, true
}

// ListTenantQuotas returns all configured tenant quotas.
func (e *LimiterEngine) ListTenantQuotas() []*TenantQuota {
	e.mu.RLock()
	defer e.mu.RUnlock()
	quotas := make([]*TenantQuota, 0, len(e.tenantQuotas))
	for _, q := range e.tenantQuotas {
		copyQ := *q
		quotas = append(quotas, &copyQ)
	}
	return quotas
}

// BanIP manually bans an IP address.
func (e *LimiterEngine) BanIP(ip string, reason string, duration time.Duration, originNode string) (*IPBanRecord, error) {
	record, err := e.ipBanStore.Ban(ip, reason, duration, originNode)
	if err != nil {
		return nil, err
	}
	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:   "ratelimit_manual_ban",
			Target:   ip,
			Actor:    "admin",
			ClientIP: "127.0.0.1",
			Status:   "success",
			Details: map[string]any{
				"reason":   reason,
				"duration": duration.String(),
			},
		})
	}
	return record, nil
}

// UnbanIP removes an IP ban.
func (e *LimiterEngine) UnbanIP(ip string) bool {
	unbanned := e.ipBanStore.Unban(ip)
	if unbanned && e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:   "ratelimit_manual_unban",
			Target:   ip,
			Actor:    "admin",
			ClientIP: "127.0.0.1",
			Status:   "success",
		})
	}
	return unbanned
}

// ListBannedIPs returns all active IP bans.
func (e *LimiterEngine) ListBannedIPs() []*IPBanRecord {
	return e.ipBanStore.ActiveBans()
}

// Status returns runtime metrics and health status.
func (e *LimiterEngine) Status() LimiterStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return LimiterStatus{
		Enabled:                 e.config.Enabled,
		TotalTenants:            len(e.tenantQuotas),
		ActiveBannedIPs:         e.ipBanStore.Count(),
		TotalEvaluations:        atomic.LoadInt64(&e.totalEvaluations),
		TotalThrottledRequests:  atomic.LoadInt64(&e.totalThrottledRequests),
		TotalBannedRejections:   atomic.LoadInt64(&e.totalBannedRejections),
		TotalBandwidthThrottled: atomic.LoadInt64(&e.totalBandwidthThrottled),
		LastSyncTime:            e.lastSyncTime,
		SyncedPeersCount:        e.syncedPeersCount,
		UptimeSeconds:           int64(time.Since(e.startTime).Seconds()),
	}
}

// Config returns the current configuration (masked).
func (e *LimiterEngine) Config() LimiterConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config.Sanitized()
}

// UpdateConfig updates rate limiter settings.
func (e *LimiterEngine) UpdateConfig(cfg LimiterConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.config = cfg
	e.globalBucket.UpdateConfig(cfg.DefaultRPS, float64(cfg.DefaultBurst))
	return nil
}

// GenerateSyncPayload creates an authenticated sync payload for mesh distribution.
func (e *LimiterEngine) GenerateSyncPayload() (*SyncPayload, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	bans := e.ipBanStore.ActiveBans()
	return BuildSyncPayload(e.nodeID, e.config.SyncSecret, bans)
}

// IngestSyncPayload validates and ingests a sync payload from a cluster peer.
func (e *LimiterEngine) IngestSyncPayload(payload *SyncPayload) (int, error) {
	if payload == nil {
		return 0, fmt.Errorf("sync payload cannot be nil")
	}

	e.mu.RLock()
	secret := e.config.SyncSecret
	e.mu.RUnlock()

	if err := VerifySignature(secret, payload, 60); err != nil {
		return 0, err
	}

	applied := IngestPeerBans(e.ipBanStore, payload.ActiveBans)

	e.mu.Lock()
	e.lastSyncTime = time.Now()
	e.syncedPeersCount++
	e.mu.Unlock()

	return applied, nil
}
