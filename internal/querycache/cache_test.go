package querycache

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCache_GetSetBasic(t *testing.T) {
	cfg := DefaultCacheConfig()
	c := NewCache(cfg)

	// Miss on non-existent key
	val, ok := c.Get("missing")
	if ok || val != nil {
		t.Fatalf("expected miss for missing key, got %v", val)
	}

	// Set and Get
	if err := c.Set("test:key", "sample-payload", 1*time.Second); err != nil {
		t.Fatalf("failed to set cache item: %v", err)
	}

	val, ok = c.Get("test:key")
	if !ok || val != "sample-payload" {
		t.Fatalf("expected sample-payload, got %v (ok=%v)", val, ok)
	}

	stats := c.Stats()
	if stats.TotalHits != 1 {
		t.Errorf("expected 1 hit, got %d", stats.TotalHits)
	}
	if stats.TotalMisses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.TotalMisses)
	}
}

func TestCache_TTLExpiration(t *testing.T) {
	cfg := DefaultCacheConfig()
	cfg.MinTTL = 10 * time.Millisecond
	cfg.DefaultTTL = 20 * time.Millisecond
	c := NewCache(cfg)

	_ = c.Set("short", "quick", 20*time.Millisecond)

	val, ok := c.Get("short")
	if !ok || val != "quick" {
		t.Fatalf("expected item present immediately, got %v", val)
	}

	time.Sleep(30 * time.Millisecond)

	val, ok = c.Get("short")
	if ok || val != nil {
		t.Fatalf("expected item expired, got %v", val)
	}
}

func TestCache_LRUEvictionMaxItems(t *testing.T) {
	cfg := DefaultCacheConfig()
	cfg.MaxItems = 3
	c := NewCache(cfg)

	_ = c.Set("k1", "v1", 10*time.Second)
	_ = c.Set("k2", "v2", 10*time.Second)
	_ = c.Set("k3", "v3", 10*time.Second)

	// Touch k1 to make k2 the LRU
	_, _ = c.Get("k1")

	// Insert k4, should evict k2
	_ = c.Set("k4", "v4", 10*time.Second)

	if _, ok := c.Get("k2"); ok {
		t.Errorf("expected k2 to be evicted, but it was found")
	}
	if _, ok := c.Get("k1"); !ok {
		t.Errorf("expected k1 to be retained")
	}
	if _, ok := c.Get("k3"); !ok {
		t.Errorf("expected k3 to be retained")
	}
	if _, ok := c.Get("k4"); !ok {
		t.Errorf("expected k4 to be retained")
	}

	stats := c.Stats()
	if stats.EvictionsTotal != 1 {
		t.Errorf("expected 1 eviction, got %d", stats.EvictionsTotal)
	}
}

func TestCache_LRUEvictionMaxMemory(t *testing.T) {
	cfg := DefaultCacheConfig()
	cfg.MaxMemoryBytes = 400 // low memory threshold to force evictions
	c := NewCache(cfg)

	_ = c.Set("large:1", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", 10*time.Second)
	_ = c.Set("large:2", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", 10*time.Second)
	_ = c.Set("large:3", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", 10*time.Second)

	stats := c.Stats()
	if stats.EvictionsTotal == 0 {
		t.Errorf("expected evictions under tight memory constraint, got %d", stats.EvictionsTotal)
	}
}

func TestCache_SingleFlightCoalescing(t *testing.T) {
	cfg := DefaultCacheConfig()
	c := NewCache(cfg)

	var computeCalls int64
	computeFn := func() (any, error) {
		time.Sleep(20 * time.Millisecond) // simulate heavy computation
		atomic.AddInt64(&computeCalls, 1)
		return "heavy-result", nil
	}

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	results := make([]any, goroutines)
	for i := 0; i < goroutines; i++ {
		idx := i
		go func() {
			defer wg.Done()
			val, err := c.GetOrCompute("metrics:cluster", 1*time.Second, computeFn)
			if err != nil {
				t.Errorf("goroutine %d failed: %v", idx, err)
			}
			results[idx] = val
		}()
	}

	wg.Wait()

	calls := atomic.LoadInt64(&computeCalls)
	if calls != 1 {
		t.Errorf("expected single compute call due to coalescing, got %d", calls)
	}

	for i, r := range results {
		if r != "heavy-result" {
			t.Errorf("goroutine %d got unexpected result: %v", i, r)
		}
	}

	stats := c.Stats()
	if stats.CoalescedCalls < int64(goroutines-1) {
		t.Errorf("expected at least %d coalesced calls, got %d", goroutines-1, stats.CoalescedCalls)
	}
}

func TestCache_SingleFlightErrorHandling(t *testing.T) {
	cfg := DefaultCacheConfig()
	c := NewCache(cfg)

	expectedErr := errors.New("backend failed")
	val, err := c.GetOrCompute("fail:key", 1*time.Second, func() (any, error) {
		return nil, expectedErr
	})

	if err != expectedErr {
		t.Fatalf("expected error %v, got %v", expectedErr, err)
	}
	if val != nil {
		t.Fatalf("expected nil value, got %v", val)
	}

	// Should not have cached the failure
	if _, ok := c.Get("fail:key"); ok {
		t.Fatal("expected failure not to be cached")
	}
}

func TestCache_DeleteAndPrefix(t *testing.T) {
	cfg := DefaultCacheConfig()
	c := NewCache(cfg)

	_ = c.Set("docker:c1", "data1", 10*time.Second)
	_ = c.Set("docker:c2", "data2", 10*time.Second)
	_ = c.Set("system:ram", "data3", 10*time.Second)

	if !c.Delete("docker:c1") {
		t.Error("expected delete to return true")
	}
	if c.Delete("docker:c1") {
		t.Error("expected second delete to return false")
	}

	deleted := c.DeletePrefix("docker:")
	if deleted != 1 {
		t.Errorf("expected 1 prefix-deleted item, got %d", deleted)
	}

	if _, ok := c.Get("docker:c2"); ok {
		t.Error("expected docker:c2 to be prefix-deleted")
	}
	if _, ok := c.Get("system:ram"); !ok {
		t.Error("expected system:ram to still exist")
	}
}

func TestCache_PurgeAndKeys(t *testing.T) {
	cfg := DefaultCacheConfig()
	c := NewCache(cfg)

	_ = c.Set("a", 1, 10*time.Second)
	_ = c.Set("b", 2, 10*time.Second)
	_ = c.Set("c", 3, 10*time.Second)

	keys := c.Keys()
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	purged := c.Purge()
	if purged != 3 {
		t.Errorf("expected 3 purged items, got %d", purged)
	}

	if len(c.Keys()) != 0 {
		t.Errorf("expected 0 keys after purge, got %d", len(c.Keys()))
	}
}

func TestCache_Concurrency(t *testing.T) {
	cfg := DefaultCacheConfig()
	c := NewCache(cfg)

	const workers = 20
	const ops = 50
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		wID := i
		go func() {
			defer wg.Done()
			for j := 0; j < ops; j++ {
				key := fmt.Sprintf("concur:%d:%d", wID%4, j%5)
				_ = c.Set(key, j, 50*time.Millisecond)
				_, _ = c.Get(key)
			}
		}()
	}

	wg.Wait()
	stats := c.Stats()
	if stats.TotalHits+stats.TotalMisses == 0 {
		t.Fatal("expected non-zero stats after concurrent load")
	}
}
