package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/querycache"
	"github.com/kLauncher1/dock-radar/internal/security"
)

type cachePurgeRequest struct {
	Prefix string `json:"prefix,omitempty"`
}

type eventPublishRequest struct {
	Type       string            `json:"type"`
	Action     string            `json:"action"`
	ActorID    string            `json:"actor_id"`
	ActorName  string            `json:"actor_name,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// handleCacheStatus returns aggregated cache and event pipeline telemetry.
func (cfg *HandlerConfig) handleCacheStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.QueryCacheEngine == nil {
		http.Error(w, "Query cache engine not configured", http.StatusServiceUnavailable)
		return
	}

	status := cfg.QueryCacheEngine.Status()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(status)
}

// handleCacheKeys returns active cached keys and their time-to-live metrics.
func (cfg *HandlerConfig) handleCacheKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.QueryCacheEngine == nil {
		http.Error(w, "Query cache engine not configured", http.StatusServiceUnavailable)
		return
	}

	keys := cfg.QueryCacheEngine.Cache().Keys()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys":  keys,
		"count": len(keys),
	})
}

// handleCachePurge evicts all or prefix-matched cache entries.
func (cfg *HandlerConfig) handleCachePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.QueryCacheEngine == nil {
		http.Error(w, "Query cache engine not configured", http.StatusServiceUnavailable)
		return
	}

	var req cachePurgeRequest
	if r.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		if len(body) > 0 {
			_ = json.Unmarshal(body, &req)
		}
	}

	var count int
	if req.Prefix != "" {
		count = cfg.QueryCacheEngine.Cache().DeletePrefix(req.Prefix)
	} else {
		count = cfg.QueryCacheEngine.PurgeCache("admin")
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":      true,
		"purged_count": count,
		"prefix":       req.Prefix,
		"message":      fmt.Sprintf("Purged %d cache entries", count),
	})
}

// handleCacheConfig handles reading or updating query cache parameters.
func (cfg *HandlerConfig) handleCacheConfig(w http.ResponseWriter, r *http.Request) {
	if cfg.QueryCacheEngine == nil {
		http.Error(w, "Query cache engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !cfg.authorize(w, r, security.RoleViewer) {
			return
		}
		cConfig := cfg.QueryCacheEngine.Cache().Config()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(cConfig)

	case http.MethodPost:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		var newCfg querycache.CacheConfig
		body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &newCfg); err != nil {
			http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
			return
		}

		if err := cfg.QueryCacheEngine.Cache().UpdateConfig(newCfg); err != nil {
			http.Error(w, fmt.Sprintf("Configuration validation error: %v", err), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"config":  newCfg,
			"message": "Query cache configuration updated",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleEventsStatus returns current multiplexer subscriber count and throughput.
func (cfg *HandlerConfig) handleEventsStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.QueryCacheEngine == nil {
		http.Error(w, "Query cache engine not configured", http.StatusServiceUnavailable)
		return
	}

	muxStats := cfg.QueryCacheEngine.Multiplexer().Stats()
	dedupStats := cfg.QueryCacheEngine.Deduplicator().Stats()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"multiplexer":  muxStats,
		"deduplicator": dedupStats,
	})
}

// handleEventsStream streams live Docker and cluster events via Server-Sent Events (SSE).
func (cfg *HandlerConfig) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.QueryCacheEngine == nil {
		http.Error(w, "Query cache engine not configured", http.StatusServiceUnavailable)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	filter := querycache.EventFilter{
		ContainerID: strings.TrimSpace(q.Get("container")),
		Type:        strings.TrimSpace(q.Get("type")),
		Action:      strings.TrimSpace(q.Get("action")),
	}

	subID := fmt.Sprintf("sse-%d", time.Now().UnixNano())
	eventCh, err := cfg.QueryCacheEngine.Multiplexer().Subscribe(subID, filter, 128)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to subscribe: %v", err), http.StatusServiceUnavailable)
		return
	}
	defer cfg.QueryCacheEngine.Multiplexer().Unsubscribe(subID)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Send initial connection greeting
	_, _ = fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"connected\",\"sub_id\":\"%s\"}\n\n", subID)
	flusher.Flush()

	notify := r.Context().Done()
	keepAliveTicker := time.NewTicker(15 * time.Second)
	defer keepAliveTicker.Stop()

	for {
		select {
		case <-notify:
			return
		case <-keepAliveTicker.C:
			_, _ = fmt.Fprintf(w, ": keep-alive\n\n")
			flusher.Flush()
		case ev, ok := <-eventCh:
			if !ok {
				return
			}
			payload, err := json.Marshal(ev)
			if err == nil {
				_, _ = fmt.Fprintf(w, "event: docker_event\ndata: %s\n\n", payload)
				flusher.Flush()
			}
		}
	}
}

// handleEventsPublish ingests an event into the multiplexer and deduplicator.
func (cfg *HandlerConfig) handleEventsPublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.QueryCacheEngine == nil {
		http.Error(w, "Query cache engine not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var req eventPublishRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	ev := querycache.DockerEvent{
		Type:       req.Type,
		Action:     req.Action,
		ActorID:    req.ActorID,
		ActorName:  req.ActorName,
		Attributes: req.Attributes,
		Time:       time.Now().Unix(),
	}

	ingested := cfg.QueryCacheEngine.IngestEvent(ev)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"ingested": ingested,
		"deduped":  !ingested,
		"message":  "Event submitted to pipeline",
	})
}

// handleEventsTest publishes a synthetic test event for verification.
func (cfg *HandlerConfig) handleEventsTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.QueryCacheEngine == nil {
		http.Error(w, "Query cache engine not configured", http.StatusServiceUnavailable)
		return
	}

	testEv := querycache.DockerEvent{
		ID:        fmt.Sprintf("test-%d", time.Now().UnixNano()),
		Type:      "container",
		Action:    "test_ping",
		ActorID:   "c-synthetic-test",
		ActorName: "dock-radar-prober",
		Time:      time.Now().Unix(),
		Attributes: map[string]string{
			"trigger": "manual_test",
		},
	}

	ingested := cfg.QueryCacheEngine.IngestEvent(testEv)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"event":    testEv,
		"ingested": ingested,
		"message":  "Synthetic test event broadcasted",
	})
}
