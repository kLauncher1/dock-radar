package querycache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
)

// Engine is the master orchestrator coordinating the adaptive query cache,
// non-blocking event multiplexer, and distributed event deduplicator.
type Engine struct {
	mu              sync.RWMutex
	cache           *Cache
	multiplexer     *EventMultiplexer
	deduplicator    *EventDeduplicator
	auditLogger     *audit.Logger
	alertDispatcher *alert.Dispatcher
	dockerClient    *docker.Client
	nodeID          string
	running         bool
	cancelFn        context.CancelFunc
}

// NewEngine constructs a fully configured query cache and event ingestion engine.
func NewEngine(
	cacheCfg CacheConfig,
	muxCfg MultiplexerConfig,
	dedupCfg DedupConfig,
	auditLogger *audit.Logger,
	alertDispatcher *alert.Dispatcher,
	dockerClient *docker.Client,
	nodeID string,
) *Engine {
	if nodeID == "" {
		nodeID = "local-node"
	}

	return &Engine{
		cache:           NewCache(cacheCfg),
		multiplexer:     NewEventMultiplexer(muxCfg),
		deduplicator:    NewEventDeduplicator(dedupCfg),
		auditLogger:     auditLogger,
		alertDispatcher: alertDispatcher,
		dockerClient:    dockerClient,
		nodeID:          nodeID,
	}
}

// Start initiates background maintenance loops for TTL expirations and deduplication window sliding.
func (e *Engine) Start(ctx context.Context) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	runCtx, cancel := context.WithCancel(ctx)
	e.cancelFn = cancel
	e.mu.Unlock()

	go e.runMaintenance(runCtx)
}

// Stop cleanly terminates background workers and closes multiplexer channels.
func (e *Engine) Stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	e.running = false
	if e.cancelFn != nil {
		e.cancelFn()
	}
	e.mu.Unlock()

	e.multiplexer.Close()
}

// runMaintenance periodically evicts expired cache items and slides the deduplication window.
func (e *Engine) runMaintenance(ctx context.Context) {
	cacheTicker := time.NewTicker(5 * time.Second)
	dedupTicker := time.NewTicker(10 * time.Second)
	defer cacheTicker.Stop()
	defer dedupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cacheTicker.C:
			e.cache.PruneExpired()
		case <-dedupTicker.C:
			e.deduplicator.PruneExpired()
		}
	}
}

// IngestEvent processes an incoming Docker or cluster event, filters duplicates,
// selectively invalidates affected cache keys, and fans out to all subscribers.
func (e *Engine) IngestEvent(ev DockerEvent) bool {
	if err := ValidateDockerEvent(&ev); err != nil {
		return false
	}

	if ev.NodeID == "" {
		ev.NodeID = e.nodeID
	}

	// 1. Check deduplication
	if e.deduplicator.IsDuplicate(ev) {
		return false
	}

	// 2. Invalidate cache entries associated with mutated container/daemon state
	e.invalidateForEvent(ev)

	// 3. Dispatch to multiplexer subscribers non-blockingly
	e.multiplexer.Publish(ev)

	// 4. Audit trail logging for container death, OOM, or restart
	if e.auditLogger != nil && (ev.Action == "die" || ev.Action == "oom" || ev.Action == "restart" || ev.Action == "kill") {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  fmt.Sprintf("event_%s", ev.Action),
			Target:  ev.ActorID,
			Details: map[string]any{"actor_name": ev.ActorName, "type": ev.Type, "node_id": ev.NodeID},
		})
	}

	// 5. Critical webhook alert dispatch for kernel OOM kills
	if e.alertDispatcher != nil && ev.Action == "oom" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = e.alertDispatcher.Dispatch(ctx, alert.Event{
			Level:     "critical",
			Source:    ev.ActorID,
			EventType: "oom_killed",
			Message:   fmt.Sprintf("Container %s (%s) was terminated by host OOM-killer", ev.ActorName, ev.ActorID),
			Details: map[string]any{
				"actor_id":   ev.ActorID,
				"actor_name": ev.ActorName,
				"exit_code":  137,
				"node_id":    ev.NodeID,
			},
			Timestamp: time.Now().UTC(),
		})
	}

	return true
}

// invalidateForEvent selectively busts cached query results based on the event scope.
func (e *Engine) invalidateForEvent(ev DockerEvent) {
	switch ev.Action {
	case "start", "die", "stop", "restart", "kill", "oom", "destroy", "create":
		// Clear cached Docker daemon status and container lists
		e.cache.DeletePrefix("docker:")
		e.cache.DeletePrefix("cluster:")
		e.cache.Delete("system:metrics")
	}
}

// Status aggregates live performance telemetry across cache, multiplexer, and deduplicator.
func (e *Engine) Status() QueryCacheStatus {
	return QueryCacheStatus{
		Enabled:      e.cache.Config().Enabled,
		Cache:        e.cache.Stats(),
		Multiplexer:  e.multiplexer.Stats(),
		Deduplicator: e.deduplicator.Stats(),
		CacheConfig:  e.cache.Config(),
		Timestamp:    time.Now().UTC(),
	}
}

// Cache returns the underlying in-memory query cache.
func (e *Engine) Cache() *Cache {
	return e.cache
}

// Multiplexer returns the underlying non-blocking event multiplexer.
func (e *Engine) Multiplexer() *EventMultiplexer {
	return e.multiplexer
}

// Deduplicator returns the underlying distributed event deduplicator.
func (e *Engine) Deduplicator() *EventDeduplicator {
	return e.deduplicator
}

// PurgeCache clears all entries from the query cache and records an audit log entry.
func (e *Engine) PurgeCache(operator string) int {
	count := e.cache.Purge()
	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:  "query_cache_purged",
			Target:  "cache",
			Details: map[string]any{"purged_items": count, "operator": operator},
		})
	}
	return count
}
