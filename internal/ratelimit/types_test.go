package ratelimit

import (
	"testing"
	"time"
)

func TestTenantQuota_Validate(t *testing.T) {
	valid := &TenantQuota{
		TenantID:          "tenant-alpha_01",
		Name:              "Alpha Tenant",
		Tier:              "Enterprise",
		RequestsPerSecond: 100,
		BurstCapacity:     200,
		WindowSeconds:     60,
		MaxBytesPerSecond: 1048576,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid quota, got error: %v", err)
	}

	// Test invalid cases
	var nilQuota *TenantQuota
	if err := nilQuota.Validate(); err == nil {
		t.Errorf("expected error on nil quota")
	}

	invalidID := &TenantQuota{
		TenantID:          "bad tenant!@#",
		RequestsPerSecond: 10,
		BurstCapacity:     20,
	}
	if err := invalidID.Validate(); err == nil {
		t.Errorf("expected error on invalid tenant id regex")
	}

	zeroRPS := &TenantQuota{
		TenantID:          "tenant1",
		RequestsPerSecond: 0,
		BurstCapacity:     20,
	}
	if err := zeroRPS.Validate(); err == nil {
		t.Errorf("expected error on zero requests_per_second")
	}

	zeroBurst := &TenantQuota{
		TenantID:          "tenant1",
		RequestsPerSecond: 10,
		BurstCapacity:     0,
	}
	if err := zeroBurst.Validate(); err == nil {
		t.Errorf("expected error on zero burst_capacity")
	}
}

func TestIPBanRecord_Validate(t *testing.T) {
	valid := &IPBanRecord{
		IP:             "192.168.1.100",
		Reason:         "Excessive 429 errors",
		ViolationCount: 15,
		BannedAt:       time.Now(),
		ExpiresAt:      time.Now().Add(15 * time.Minute),
		OriginNode:     "node-1",
		Active:         true,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid IP ban record, got error: %v", err)
	}

	// Loopback IP ban should be rejected
	loopback := &IPBanRecord{
		IP: "127.0.0.1",
	}
	if err := loopback.Validate(); err == nil {
		t.Errorf("expected error banning loopback IP")
	}

	// Invalid IP format
	invalidIP := &IPBanRecord{
		IP: "999.999.999.999",
	}
	if err := invalidIP.Validate(); err == nil {
		t.Errorf("expected error on invalid IP format")
	}
}

func TestLimiterConfig_Sanitized(t *testing.T) {
	cfg := DefaultLimiterConfig()
	cfg.SyncSecret = "super-secret-cluster-token"

	sanitized := cfg.Sanitized()
	if sanitized.SyncSecret != "********" {
		t.Errorf("expected masked secret, got %s", sanitized.SyncSecret)
	}
	if cfg.SyncSecret != "super-secret-cluster-token" {
		t.Errorf("original secret was modified")
	}
}
