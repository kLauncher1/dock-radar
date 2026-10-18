package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
)

func TestScannerEngine_ScanImageAndCache(t *testing.T) {
	cfg := DefaultScannerConfig()
	cfg.Enabled = true
	cfg.AutoScan = false

	auditLogger := audit.NewLogger(100)
	alertStore := alert.NewConfigStore(alert.DefaultConfig())
	alertDispatcher := alert.NewDispatcher(alertStore)

	engine := NewEngine(cfg, nil, alertDispatcher, auditLogger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Scan alpine test image
	report, err := engine.ScanImage(ctx, "alpine:3.18")
	if err != nil {
		t.Fatalf("ScanImage failed: %v", err)
	}

	if report.OSName != "Alpine Linux" {
		t.Errorf("expected OSName Alpine Linux, got %s", report.OSName)
	}
	if len(report.Packages) == 0 {
		t.Errorf("expected discovered packages, got 0")
	}

	// Verify cached
	cached, ok := engine.GetReport("alpine:3.18")
	if !ok || cached.ID != report.ID {
		t.Errorf("expected report to be retrieved from cache")
	}

	// Verify status metrics
	status := engine.GetStatus()
	if status.TotalScannedImages != 1 {
		t.Errorf("status.TotalScannedImages = %d; want 1", status.TotalScannedImages)
	}
}

func TestScannerEngine_ListReportsFilter(t *testing.T) {
	cfg := DefaultScannerConfig()
	engine := NewEngine(cfg, nil, nil, nil)
	ctx := context.Background()

	_, _ = engine.ScanImage(ctx, "alpine:3.18")
	_, _ = engine.ScanImage(ctx, "node:20-alpine")
	_, _ = engine.ScanImage(ctx, "ubuntu:22.04")

	allReports := engine.ListReports(ScanFilter{})
	if len(allReports) != 3 {
		t.Errorf("expected 3 reports, got %d", len(allReports))
	}

	alpineFilter := engine.ListReports(ScanFilter{ImageName: "alpine"})
	if len(alpineFilter) != 2 {
		t.Errorf("expected 2 alpine reports, got %d", len(alpineFilter))
	}

	limitFilter := engine.ListReports(ScanFilter{Limit: 1})
	if len(limitFilter) != 1 {
		t.Errorf("expected 1 report with limit=1, got %d", len(limitFilter))
	}
}

func TestScannerEngine_ConfigMutation(t *testing.T) {
	cfg := DefaultScannerConfig()
	engine := NewEngine(cfg, nil, nil, nil)

	newPolicy := DefaultGatingPolicy()
	newPolicy.MaxCritical = 5
	if err := engine.UpdateGatingPolicy(newPolicy); err != nil {
		t.Fatalf("UpdateGatingPolicy failed: %v", err)
	}

	retrieved := engine.GetGatingPolicy()
	if retrieved.MaxCritical != 5 {
		t.Errorf("MaxCritical = %d; want 5", retrieved.MaxCritical)
	}
}
