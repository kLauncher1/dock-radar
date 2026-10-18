package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
)

func TestLimiterEngine_CheckRequest_Allowed(t *testing.T) {
	cfg := DefaultLimiterConfig()
	cfg.DefaultRPS = 100
	cfg.DefaultBurst = 50
	logger := audit.NewLogger(100)
	engine := NewLimiterEngine(cfg, "test-node-1", nil, logger)

	allowed, reason, retryAfter := engine.CheckRequest("tenant-a", "192.168.1.50", 1, 0)
	if !allowed {
		t.Fatalf("expected request to be allowed, got failure reason: %s (retryAfter: %v)", reason, retryAfter)
	}

	status := engine.Status()
	if status.TotalEvaluations != 1 {
		t.Fatalf("expected 1 evaluation, got %d", status.TotalEvaluations)
	}
}

func TestLimiterEngine_CheckRequest_BannedIP(t *testing.T) {
	cfg := DefaultLimiterConfig()
	engine := NewLimiterEngine(cfg, "test-node-1", nil, nil)
	clientIP := "198.51.100.123"

	// Ban the client IP
	_, err := engine.BanIP(clientIP, "Excessive unauthorized attempts", 5*time.Minute, "test-node-1")
	if err != nil {
		t.Fatalf("failed to ban IP: %v", err)
	}

	allowed, reason, _ := engine.CheckRequest("tenant-a", clientIP, 1, 0)
	if allowed {
		t.Fatalf("expected request from banned IP to be blocked")
	}
	if reason == "" {
		t.Fatalf("expected reason for blocked request")
	}

	status := engine.Status()
	if status.TotalBannedRejections != 1 {
		t.Fatalf("expected 1 banned rejection, got %d", status.TotalBannedRejections)
	}
}

func TestLimiterEngine_TenantQuota_Throttling(t *testing.T) {
	cfg := DefaultLimiterConfig()
	engine := NewLimiterEngine(cfg, "test-node-1", nil, nil)

	// Set a very strict quota for tenant-strict
	quota := TenantQuota{
		TenantID:          "tenant-strict",
		Name:              "Strict Testing Tenant",
		Tier:              "Free",
		RequestsPerSecond: 2.0,
		BurstCapacity:     2,
		WindowSeconds:     60,
	}
	err := engine.SetTenantQuota(quota)
	if err != nil {
		t.Fatalf("failed to set tenant quota: %v", err)
	}

	// Consume burst capacity (2 requests)
	for i := 0; i < 2; i++ {
		allowed, _, _ := engine.CheckRequest("tenant-strict", "10.0.0.1", 1, 0)
		if !allowed {
			t.Fatalf("request %d should have been allowed", i)
		}
	}

	// 3rd request should be throttled
	allowed, reason, retryAfter := engine.CheckRequest("tenant-strict", "10.0.0.1", 1, 0)
	if allowed {
		t.Fatalf("expected 3rd request to be throttled")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected non-zero retryAfter")
	}
	if reason == "" {
		t.Fatalf("expected failure reason")
	}

	status := engine.Status()
	if status.TotalThrottledRequests < 1 {
		t.Fatalf("expected at least 1 throttled request recorded")
	}
}

func TestLimiterEngine_BandwidthThrottling(t *testing.T) {
	cfg := DefaultLimiterConfig()
	engine := NewLimiterEngine(cfg, "test-node-1", nil, nil)

	quota := TenantQuota{
		TenantID:          "tenant-bandwidth",
		RequestsPerSecond: 100,
		BurstCapacity:     100,
		MaxBytesPerSecond: 1024, // 1 KB/s
	}
	_ = engine.SetTenantQuota(quota)

	// First 800 bytes allowed
	allowed, _, _ := engine.CheckRequest("tenant-bandwidth", "10.0.0.2", 1, 800)
	if !allowed {
		t.Fatalf("expected 800 bytes request to be allowed")
	}

	// Next 400 bytes exceeds 1024 limit
	allowed, reason, _ := engine.CheckRequest("tenant-bandwidth", "10.0.0.2", 1, 400)
	if allowed {
		t.Fatalf("expected request exceeding bandwidth limit to be throttled")
	}
	if reason == "" {
		t.Fatalf("expected failure reason on bandwidth throttle")
	}
}

func TestLimiterEngine_MeshSyncLifecycle(t *testing.T) {
	secret := "shared-cluster-secret"
	cfg1 := DefaultLimiterConfig()
	cfg1.SyncSecret = secret
	engine1 := NewLimiterEngine(cfg1, "node-1", nil, nil)

	cfg2 := DefaultLimiterConfig()
	cfg2.SyncSecret = secret
	engine2 := NewLimiterEngine(cfg2, "node-2", nil, nil)

	// Node 1 bans an abusive IP
	_, err := engine1.BanIP("198.51.100.88", "Mesh sync test ban", 10*time.Minute, "node-1")
	if err != nil {
		t.Fatalf("failed to ban on node 1: %v", err)
	}

	// Generate sync payload from node 1
	payload, err := engine1.GenerateSyncPayload()
	if err != nil {
		t.Fatalf("failed to generate sync payload: %v", err)
	}

	// Ingest payload into node 2
	applied, err := engine2.IngestSyncPayload(payload)
	if err != nil {
		t.Fatalf("failed to ingest payload on node 2: %v", err)
	}
	if applied != 1 {
		t.Fatalf("expected 1 ban applied on node 2, got %d", applied)
	}

	// Node 2 should now have the IP banned
	banned, record := engine2.ipBanStore.IsBanned("198.51.100.88")
	if !banned || record == nil {
		t.Fatalf("expected IP to be banned on node 2 after sync")
	}
	if record.OriginNode != "node-1" {
		t.Fatalf("expected origin node node-1, got %s", record.OriginNode)
	}
}

func TestLimiterEngine_CRUDAndLifecycle(t *testing.T) {
	cfg := DefaultLimiterConfig()
	engine := NewLimiterEngine(cfg, "node-crud", nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx)
	defer engine.Stop()

	// Create quota
	q := TenantQuota{
		TenantID:          "test-crud-tenant",
		Name:              "CRUD Tenant",
		Tier:              "Enterprise",
		RequestsPerSecond: 50,
		BurstCapacity:     100,
	}
	if err := engine.SetTenantQuota(q); err != nil {
		t.Fatalf("failed to set quota: %v", err)
	}

	fetched, ok := engine.GetTenantQuota("test-crud-tenant")
	if !ok || fetched.Tier != "Enterprise" {
		t.Fatalf("expected fetched tenant quota to match")
	}

	all := engine.ListTenantQuotas()
	if len(all) != 1 {
		t.Fatalf("expected 1 tenant quota, got %d", len(all))
	}

	deleted := engine.DeleteTenantQuota("test-crud-tenant")
	if !deleted {
		t.Fatalf("expected tenant quota to be deleted")
	}

	_, ok = engine.GetTenantQuota("test-crud-tenant")
	if ok {
		t.Fatalf("expected deleted tenant quota to not exist")
	}
}
