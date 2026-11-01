package crash

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
)

func TestEngine_IngestAndDeduplication(t *testing.T) {
	cfg := DefaultCrashConfig()
	cfg.MaxReports = 10
	cfg.DedupWindow = 5 * time.Minute

	logger := audit.NewLogger(100)
	cfgStore := alert.NewConfigStore(alert.DefaultConfig())
	dispatcher := alert.NewDispatcher(cfgStore)

	engine := NewEngine(cfg, dispatcher, logger, nil)

	ctx := context.Background()
	rawCrash := []byte(`Program received signal SIGSEGV, Segmentation fault.
0x0000000000401142 in execute_query (query=0x0) at db.c:89
#0  0x0000000000401142 in execute_query (query=0x0) at db.c:89
#1  0x0000000000401280 in handle_request (req=0x7ffe) at server.c:142`)

	// 1st ingestion: new crash report
	rep1, err := engine.IngestCrashDump(ctx, "c-postgres", "postgres-prod", "postgres:15", rawCrash, nil)
	if err != nil {
		t.Fatalf("first ingestion failed: %v", err)
	}
	if rep1.Signal != "SIGSEGV" || rep1.RootCause != RootCauseNullPointer || rep1.Severity != SeverityCritical {
		t.Errorf("unexpected crash classification: sig=%s cause=%s sev=%s", rep1.Signal, rep1.RootCause, rep1.Severity)
	}
	if rep1.DeduplicatedCount != 1 {
		t.Errorf("expected dedup count 1, got %d", rep1.DeduplicatedCount)
	}

	// 2nd ingestion of identical crash: should deduplicate
	rep2, err := engine.IngestCrashDump(ctx, "c-postgres", "postgres-prod", "postgres:15", rawCrash, nil)
	if err != nil {
		t.Fatalf("second ingestion failed: %v", err)
	}
	if rep2.DeduplicatedCount != 2 {
		t.Errorf("expected dedup count 2, got %d", rep2.DeduplicatedCount)
	}
	if rep2.Signature != rep1.Signature {
		t.Errorf("signatures should match: %s != %s", rep2.Signature, rep1.Signature)
	}

	// Verify status
	status := engine.Status()
	if status.TotalCrashes != 2 {
		t.Errorf("expected total crashes 2, got %d", status.TotalCrashes)
	}
	if status.DedupedCount != 1 {
		t.Errorf("expected deduped count 1, got %d", status.DedupedCount)
	}
	if status.UniqueSignatures != 1 {
		t.Errorf("expected unique signatures 1, got %d", status.UniqueSignatures)
	}
	if status.ReportsStored != 1 {
		t.Errorf("expected reports stored 1, got %d", status.ReportsStored)
	}

	// Verify reports filter
	reports := engine.Reports(ReportFilter{ContainerID: "c-postgres"})
	if len(reports) != 1 {
		t.Fatalf("expected 1 filtered report, got %d", len(reports))
	}
	if reports[0].ID != rep1.ID {
		t.Errorf("report ID mismatch: %s != %s", reports[0].ID, rep1.ID)
	}

	// Verify audit log recorded event
	recentAudit := logger.Recent(10, "")
	foundAudit := false
	for _, a := range recentAudit {
		if a.Action == "container_crash_intercepted" && a.Target == "c-postgres" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Errorf("expected audit event for container_crash_intercepted")
	}
}

func TestEngine_TriggerTestCrash(t *testing.T) {
	cfg := DefaultCrashConfig()
	engine := NewEngine(cfg, nil, nil, nil)

	rep, err := engine.TriggerTestCrash("test-container-99")
	if err != nil {
		t.Fatalf("TriggerTestCrash failed: %v", err)
	}

	if rep.ContainerID != "test-container-99" {
		t.Errorf("expected container ID test-container-99, got %s", rep.ContainerID)
	}
	if rep.Signal != "SIGSEGV" || rep.RootCause != RootCauseNullPointer {
		t.Errorf("expected SIGSEGV / null_pointer_dereference, got %s / %s", rep.Signal, rep.RootCause)
	}
	if len(rep.Backtrace.Frames) < 3 {
		t.Errorf("expected at least 3 stack frames in test crash, got %d", len(rep.Backtrace.Frames))
	}

	// Check report lookup
	lookedUp, ok := engine.Report(rep.ID)
	if !ok || lookedUp == nil {
		t.Fatalf("expected Report(%q) to find report", rep.ID)
	}
	if lookedUp.ID != rep.ID {
		t.Errorf("ID mismatch: %s != %s", lookedUp.ID, rep.ID)
	}

	// Clear reports
	engine.ClearReports()
	if len(engine.Reports(ReportFilter{})) != 0 {
		t.Errorf("expected 0 reports after ClearReports")
	}
}

func TestEngine_LifecycleAndConfig(t *testing.T) {
	cfg := DefaultCrashConfig()
	engine := NewEngine(cfg, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	engine.Start(ctx)

	// Update config
	newCfg := engine.Config()
	newCfg.MaxReports = 50
	newCfg.WatchDirectory = "data/custom_cores"
	if err := engine.UpdateConfig(newCfg); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	updated := engine.Config()
	if updated.MaxReports != 50 || updated.WatchDirectory != "data/custom_cores" {
		t.Errorf("config not updated: %+v", updated)
	}

	cancel()
	engine.Stop()
}

func TestEngine_DisabledRejection(t *testing.T) {
	cfg := DefaultCrashConfig()
	cfg.Enabled = false
	engine := NewEngine(cfg, nil, nil, nil)

	_, err := engine.IngestCrashDump(context.Background(), "c1", "n1", "img", []byte("some crash"), nil)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Errorf("expected error when engine is disabled, got %v", err)
	}
}
