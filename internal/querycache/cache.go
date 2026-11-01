package querycache

import (
	"container/list"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// cacheEntry represents an in-memory cached value with LRU tracking and expiration.
type cacheEntry struct {
	key          string
	value        any
	sizeBytes    int64
	hitCount     int64
	createdAt    time.Time
	expiresAt    time.Time
	lastAccessed time.Time
	element      *list.Element
}

// singleFlightCall tracks an in-flight computation to prevent thundering herd.
type singleFlightCall struct {
	wg  sync.WaitGroup
	val any
	err error
}

// Cache provides a thread-safe, memory-bounded, LRU-evicting in-memory query cache
// with adaptive TTL tuning and single-flight request coalescing.
type Cache struct {
	mu          sync.RWMutex
	cfg         CacheConfig
	items       map[string]*cacheEntry
	lruList     *list.List
	totalBytes  int64
	hits        int64
	misses      int64
	evictions   int64
	coalesced   int64
	flightMu    sync.Mutex
	flightCalls map[string]*singleFlightCall
}

// NewCache constructs an active query cache with the specified configuration.
func NewCache(cfg CacheConfig) *Cache {
	if err := ValidateCacheConfig(cfg); err != nil {
		cfg = DefaultCacheConfig()
	}
	return &Cache{
		cfg:         cfg,
		items:       make(map[string]*cacheEntry),
		lruList:     list.New(),
		flightCalls: make(map[string]*singleFlightCall),
	}
}

// estimateSize calculates the approximate memory footprint of a cached entry.
func estimateSize(key string, val any) int64 {
	base := int64(len(key) + 96) // entry struct and list overhead
	switch v := val.(type) {
	case string:
		return base + int64(len(v))
	case []byte:
		return base + int64(len(v))
	case int, int64, float64, bool:
		return base + 16
	case fmt.Stringer:
		return base + int64(len(v.String()))
	default:
		return base + 256
	}
}

// Get retrieves an item from cache if present and unexpired.
func (c *Cache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.items[key]
	if !ok {
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	now := time.Now()
	if now.After(entry.expiresAt) {
		c.removeEntry(entry)
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	entry.hitCount++
	entry.lastAccessed = now
	c.lruList.MoveToFront(entry.element)
	atomic.AddInt64(&c.hits, 1)
	return entry.value, true
}

// Set inserts or updates an entry in the cache with the given or calculated TTL.
func (c *Cache) Set(key string, val any, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.cfg.Enabled {
		return nil
	}

	now := time.Now()
	effectiveTTL := c.resolveTTL(key, ttl)
	size := estimateSize(key, val)

	// If entry already exists, update and adjust memory accounting
	if existing, ok := c.items[key]; ok {
		c.totalBytes -= existing.sizeBytes
		existing.value = val
		existing.sizeBytes = size
		existing.expiresAt = now.Add(effectiveTTL)
		existing.lastAccessed = now
		c.totalBytes += size
		c.lruList.MoveToFront(existing.element)
		c.enforceCapacity()
		return nil
	}

	// Evict to make room if over bounds
	c.enforceCapacityForNew(size)

	entry := &cacheEntry{
		key:          key,
		value:        val,
		sizeBytes:    size,
		hitCount:     0,
		createdAt:    now,
		expiresAt:    now.Add(effectiveTTL),
		lastAccessed: now,
	}

	elem := c.lruList.PushFront(entry)
	entry.element = elem
	c.items[key] = entry
	c.totalBytes += size

	c.enforceCapacity()
	return nil
}

// resolveTTL applies adaptive tuning or bounds limits to the requested TTL.
func (c *Cache) resolveTTL(key string, requested time.Duration) time.Duration {
	ttl := requested
	if ttl <= 0 {
		ttl = c.cfg.DefaultTTL
	}

	if c.cfg.AdaptiveTuning {
		// If key was recently hit heavily, extend TTL slightly to buffer scraper bursts
		if entry, exists := c.items[key]; exists && entry.hitCount > 5 {
			ttl = ttl * 3 / 2
		}
	}

	if ttl < c.cfg.MinTTL {
		ttl = c.cfg.MinTTL
	}
	if ttl > c.cfg.MaxTTL {
		ttl = c.cfg.MaxTTL
	}
	return ttl
}

// enforceCapacity evicts items from the tail until within configured bounds.
func (c *Cache) enforceCapacity() {
	for (len(c.items) > c.cfg.MaxItems || c.totalBytes > c.cfg.MaxMemoryBytes) && c.lruList.Len() > 0 {
		tailElem := c.lruList.Back()
		if tailElem == nil {
			break
		}
		entry := tailElem.Value.(*cacheEntry)
		c.removeEntry(entry)
		atomic.AddInt64(&c.evictions, 1)
	}
}

// enforceCapacityForNew frees memory prior to inserting a new item of estimated size.
func (c *Cache) enforceCapacityForNew(newSize int64) {
	for (len(c.items) >= c.cfg.MaxItems || (c.totalBytes+newSize) > c.cfg.MaxMemoryBytes) && c.lruList.Len() > 0 {
		tailElem := c.lruList.Back()
		if tailElem == nil {
			break
		}
		entry := tailElem.Value.(*cacheEntry)
		c.removeEntry(entry)
		atomic.AddInt64(&c.evictions, 1)
	}
}

// removeEntry unlinks and cleans up an entry (must be called with lock held).
func (c *Cache) removeEntry(entry *cacheEntry) {
	delete(c.items, entry.key)
	c.lruList.Remove(entry.element)
	c.totalBytes -= entry.sizeBytes
	if c.totalBytes < 0 {
		c.totalBytes = 0
	}
}

// GetOrCompute coordinates concurrent readers: if cached, returns immediately;
// otherwise coalesces multiple in-flight callers into a single invocation of computeFn.
func (c *Cache) GetOrCompute(key string, ttl time.Duration, computeFn func() (any, error)) (any, error) {
	if val, ok := c.Get(key); ok {
		return val, nil
	}

	c.flightMu.Lock()
	if call, inFlight := c.flightCalls[key]; inFlight {
		c.flightMu.Unlock()
		atomic.AddInt64(&c.coalesced, 1)
		call.wg.Wait()
		return call.val, call.err
	}

	call := &singleFlightCall{}
	call.wg.Add(1)
	c.flightCalls[key] = call
	c.flightMu.Unlock()

	defer func() {
		c.flightMu.Lock()
		delete(c.flightCalls, key)
		c.flightMu.Unlock()
		call.wg.Done()
	}()

	computedVal, err := computeFn()
	if err != nil {
		call.err = err
		return nil, err
	}

	_ = c.Set(key, computedVal, ttl)
	call.val = computedVal
	return computedVal, nil
}

// Delete explicitly invalidates a single key.
func (c *Cache) Delete(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[key]; ok {
		c.removeEntry(entry)
		return true
	}
	return false
}

// DeletePrefix invalidates all keys that start with the given prefix.
func (c *Cache) DeletePrefix(prefix string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	var targets []*cacheEntry
	for k, entry := range c.items {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			targets = append(targets, entry)
		}
	}

	for _, entry := range targets {
		c.removeEntry(entry)
	}
	return len(targets)
}

// Purge evicts all entries from the cache.
func (c *Cache) Purge() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := len(c.items)
	c.items = make(map[string]*cacheEntry)
	c.lruList.Init()
	c.totalBytes = 0
	return count
}

// Keys returns a snapshot of active, unexpired keys and their metadata.
func (c *Cache) Keys() []CacheItemSummary {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	var list []CacheItemSummary
	for _, entry := range c.items {
		if now.Before(entry.expiresAt) {
			list = append(list, CacheItemSummary{
				Key:          entry.key,
				HitCount:     entry.hitCount,
				SizeBytes:    entry.sizeBytes,
				ExpiresIn:    entry.expiresAt.Sub(now),
				CreatedAt:    entry.createdAt,
				LastAccessed: entry.lastAccessed,
			})
		}
	}
	return list
}

// Stats returns a current telemetry snapshot of cache hits, misses, and memory footprint.
func (c *Cache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hits := atomic.LoadInt64(&c.hits)
	misses := atomic.LoadInt64(&c.misses)
	total := hits + misses
	var ratio float64
	if total > 0 {
		ratio = float64(hits) / float64(total) * 100.0
	}

	return CacheStats{
		TotalHits:      hits,
		TotalMisses:    misses,
		HitRatio:       ratio,
		ItemCount:      len(c.items),
		MemoryBytes:    c.totalBytes,
		EvictionsTotal: atomic.LoadInt64(&c.evictions),
		CoalescedCalls: atomic.LoadInt64(&c.coalesced),
	}
}

// PruneExpired purges stale records and returns the number of cleaned items.
func (c *Cache) PruneExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var expired []*cacheEntry
	for _, entry := range c.items {
		if now.After(entry.expiresAt) {
			expired = append(expired, entry)
		}
	}

	for _, entry := range expired {
		c.removeEntry(entry)
	}
	return len(expired)
}

// Config returns a copy of the current configuration.
func (c *Cache) Config() CacheConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg
}

// UpdateConfig applies validated configuration updates at runtime.
func (c *Cache) UpdateConfig(cfg CacheConfig) error {
	if err := ValidateCacheConfig(cfg); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg = cfg
	c.enforceCapacity()
	return nil
}
