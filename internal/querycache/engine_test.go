package querycache

import (
	"context"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
)

func TestEngine_Lifecycle(t *testing.T) {
	auditLogger := audit.NewLogger(100)
	alertStore := alert.NewConfigStore(alert.DefaultConfig())
	alertDispatcher := alert.NewDispatcher(alertStore)

	engine := NewEngine(
		DefaultCacheConfig(),
		DefaultMultiplexerConfig(),
		DefaultDedupConfig(),
		auditLogger,
		alertDispatcher,
		nil,
		"test-node",
	)

	ctx, cancel := context.WithCancel(context.Background())
	engine.Start(ctx)

	status := engine.Status()
	if !status.Enabled {
		t.Error("expected engine to be enabled")
	}

	cancel()
	engine.Stop()
}

func TestEngine_IngestEventAndCacheInvalidation(t *testing.T) {
	auditLogger := audit.NewLogger(100)
	engine := NewEngine(
		DefaultCacheConfig(),
		DefaultMultiplexerConfig(),
		DefaultDedupConfig(),
		auditLogger,
		nil,
		nil,
		"test-node",
	)

	// Populate cache
	_ = engine.Cache().Set("docker:containers", "cached-data", 10*time.Second)
	_ = engine.Cache().Set("system:metrics", "sys-data", 10*time.Second)
	_ = engine.Cache().Set("other:data", "keep-data", 10*time.Second)

	// Subscribe to multiplexer
	ch, err := engine.Multiplexer().Subscribe("sub-engine", EventFilter{}, 10)
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}

	// Ingest container die event
	ev := DockerEvent{
		ID:        "evt-die-1",
		Type:      "container",
		Action:    "die",
		ActorID:   "c-app",
		ActorName: "web",
		Time:      time.Now().Unix(),
	}

	if !engine.IngestEvent(ev) {
		t.Fatal("expected first event ingestion to succeed")
	}

	// Verify event delivered to subscriber
	select {
	case received := <-ch:
		if received.ID != "evt-die-1" {
			t.Errorf("expected evt-die-1, got %s", received.ID)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("subscriber did not receive event")
	}

	// Verify cache entries invalidated
	if _, ok := engine.Cache().Get("docker:containers"); ok {
		t.Error("expected docker:containers to be invalidated")
	}
	if _, ok := engine.Cache().Get("system:metrics"); ok {
		t.Error("expected system:metrics to be invalidated")
	}
	if _, ok := engine.Cache().Get("other:data"); !ok {
		t.Error("expected other:data to be retained")
	}

	// Ingest exact duplicate: should be suppressed
	if engine.IngestEvent(ev) {
		t.Error("expected duplicate event to be suppressed by deduplicator")
	}
}

func TestEngine_PurgeCache(t *testing.T) {
	auditLogger := audit.NewLogger(100)
	engine := NewEngine(
		DefaultCacheConfig(),
		DefaultMultiplexerConfig(),
		DefaultDedupConfig(),
		auditLogger,
		nil,
		nil,
		"node-1",
	)

	_ = engine.Cache().Set("k1", 1, 10*time.Second)
	_ = engine.Cache().Set("k2", 2, 10*time.Second)

	purged := engine.PurgeCache("admin-tester")
	if purged != 2 {
		t.Errorf("expected 2 purged items, got %d", purged)
	}

	logs := auditLogger.Recent(10, "")
	if len(logs) == 0 || logs[0].Action != "query_cache_purged" {
		t.Errorf("expected audit log for cache purge, got %+v", logs)
	}
}
