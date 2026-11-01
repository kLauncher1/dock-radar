package querycache

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// BackpressureDropPolicy defines how the multiplexer behaves when a subscriber buffer overflows.
type BackpressureDropPolicy string

const (
	DropOldest BackpressureDropPolicy = "drop_oldest"
	DropNewest BackpressureDropPolicy = "drop_newest"
)

// CacheConfig specifies tuning parameters for the in-memory query cache.
type CacheConfig struct {
	Enabled         bool          `json:"enabled"`
	DefaultTTL      time.Duration `json:"default_ttl"`
	MinTTL          time.Duration `json:"min_ttl"`
	MaxTTL          time.Duration `json:"max_ttl"`
	MaxItems        int           `json:"max_items"`
	MaxMemoryBytes  int64         `json:"max_memory_bytes"`
	AdaptiveTuning  bool          `json:"adaptive_tuning"`
}

// DefaultCacheConfig returns optimal defaults for high-frequency Prometheus and dashboard scraping.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		Enabled:        true,
		DefaultTTL:     2 * time.Second,
		MinTTL:         500 * time.Millisecond,
		MaxTTL:         10 * time.Second,
		MaxItems:       5000,
		MaxMemoryBytes: 64 * 1024 * 1024, // 64 MB
		AdaptiveTuning: true,
	}
}

// ValidateCacheConfig checks sanity bounds for cache configuration.
func ValidateCacheConfig(cfg CacheConfig) error {
	if cfg.DefaultTTL <= 0 {
		return errors.New("default_ttl must be positive")
	}
	if cfg.MinTTL <= 0 {
		return errors.New("min_ttl must be positive")
	}
	if cfg.MaxTTL < cfg.MinTTL {
		return errors.New("max_ttl cannot be less than min_ttl")
	}
	if cfg.MaxItems <= 0 {
		return errors.New("max_items must be positive")
	}
	if cfg.MaxMemoryBytes <= 0 {
		return errors.New("max_memory_bytes must be positive")
	}
	return nil
}

// CacheItemSummary describes a single cached item for inspection APIs.
type CacheItemSummary struct {
	Key          string        `json:"key"`
	HitCount     int64         `json:"hit_count"`
	SizeBytes    int64         `json:"size_bytes"`
	ExpiresIn    time.Duration `json:"expires_in"`
	CreatedAt    time.Time     `json:"created_at"`
	LastAccessed time.Time     `json:"last_accessed"`
}

// CacheStats contains aggregated performance telemetry for the query cache.
type CacheStats struct {
	TotalHits      int64   `json:"total_hits"`
	TotalMisses    int64   `json:"total_misses"`
	HitRatio       float64 `json:"hit_ratio"`
	ItemCount      int     `json:"item_count"`
	MemoryBytes    int64   `json:"memory_bytes"`
	EvictionsTotal int64   `json:"evictions_total"`
	CoalescedCalls int64   `json:"coalesced_calls"`
}

// DockerEvent encapsulates a lifecycle or telemetry event from the Docker daemon or cluster.
type DockerEvent struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`        // "container", "image", "network", "daemon"
	Action     string            `json:"action"`      // "start", "die", "restart", "oom", "kill", "stop", "pause"
	ActorID    string            `json:"actor_id"`    // container/image ID
	ActorName  string            `json:"actor_name"`  // human-readable container name
	Time       int64             `json:"time"`        // unix timestamp in seconds or nanos
	Attributes map[string]string `json:"attributes,omitempty"`
	NodeID     string            `json:"node_id,omitempty"`
}

// ValidateDockerEvent ensures required fields and character safety on ingested events.
func ValidateDockerEvent(ev *DockerEvent) error {
	if ev == nil {
		return errors.New("event payload cannot be nil")
	}
	if strings.TrimSpace(ev.Action) == "" {
		return errors.New("event action is required")
	}
	if strings.TrimSpace(ev.ActorID) == "" && strings.TrimSpace(ev.ActorName) == "" {
		return errors.New("event must have actor_id or actor_name")
	}
	if ev.Type == "" {
		ev.Type = "container"
	}
	if ev.Time <= 0 {
		ev.Time = time.Now().Unix()
	}
	return nil
}

// EventFilter specifies matching criteria for event multiplexer subscriptions.
type EventFilter struct {
	ContainerID string `json:"container_id,omitempty"`
	Type        string `json:"type,omitempty"`
	Action      string `json:"action,omitempty"`
}

// Matches returns true if the event satisfies the subscription filter.
func (f EventFilter) Matches(ev DockerEvent) bool {
	if f.ContainerID != "" && ev.ActorID != f.ContainerID && !strings.Contains(ev.ActorName, f.ContainerID) {
		return false
	}
	if f.Type != "" && !strings.EqualFold(ev.Type, f.Type) {
		return false
	}
	if f.Action != "" && !strings.EqualFold(ev.Action, f.Action) {
		return false
	}
	return true
}

// MultiplexerConfig controls the event multiplexer buffer and backpressure behavior.
type MultiplexerConfig struct {
	Enabled        bool                   `json:"enabled"`
	BufferSize     int                    `json:"buffer_size"`
	DropPolicy     BackpressureDropPolicy `json:"drop_policy"`
	MaxSubscribers int                    `json:"max_subscribers"`
}

// DefaultMultiplexerConfig provides recommended event multiplexer defaults.
func DefaultMultiplexerConfig() MultiplexerConfig {
	return MultiplexerConfig{
		Enabled:        true,
		BufferSize:     1024,
		DropPolicy:     DropOldest,
		MaxSubscribers: 256,
	}
}

// ValidateMultiplexerConfig validates multiplexer settings.
func ValidateMultiplexerConfig(cfg MultiplexerConfig) error {
	if cfg.BufferSize <= 0 {
		return errors.New("buffer_size must be positive")
	}
	if cfg.MaxSubscribers <= 0 {
		return errors.New("max_subscribers must be positive")
	}
	if cfg.DropPolicy != DropOldest && cfg.DropPolicy != DropNewest {
		return fmt.Errorf("invalid drop_policy: %s", cfg.DropPolicy)
	}
	return nil
}

// MultiplexerStats aggregates metrics across all event subscribers.
type MultiplexerStats struct {
	ActiveSubscribers int   `json:"active_subscribers"`
	TotalIngested     int64 `json:"total_ingested"`
	TotalDispatched   int64 `json:"total_dispatched"`
	TotalDropped      int64 `json:"total_dropped"`
	QueueDepth        int   `json:"queue_depth"`
}

// DedupConfig configures distributed event deduplication parameters.
type DedupConfig struct {
	Enabled    bool          `json:"enabled"`
	Window     time.Duration `json:"window"`
	MaxTracked int           `json:"max_tracked"`
}

// DefaultDedupConfig provides standard 30-second sliding-window deduplication settings.
func DefaultDedupConfig() DedupConfig {
	return DedupConfig{
		Enabled:    true,
		Window:     30 * time.Second,
		MaxTracked: 10000,
	}
}

// ValidateDedupConfig ensures valid deduplication configuration parameters.
func ValidateDedupConfig(cfg DedupConfig) error {
	if cfg.Window <= 0 {
		return errors.New("window must be positive")
	}
	if cfg.MaxTracked <= 0 {
		return errors.New("max_tracked must be positive")
	}
	return nil
}

// DedupStats reports event deduplication throughput and suppression metrics.
type DedupStats struct {
	TotalChecked  int64 `json:"total_checked"`
	TotalDeduped  int64 `json:"total_deduped"`
	TotalUnique   int64 `json:"total_unique"`
	ActiveTracked int   `json:"active_tracked"`
}

// QueryCacheStatus represents comprehensive telemetry across query cache and event pipeline.
type QueryCacheStatus struct {
	Enabled      bool              `json:"enabled"`
	Cache        CacheStats        `json:"cache"`
	Multiplexer  MultiplexerStats  `json:"multiplexer"`
	Deduplicator DedupStats        `json:"deduplicator"`
	CacheConfig  CacheConfig       `json:"cache_config"`
	Timestamp    time.Time         `json:"timestamp"`
}
