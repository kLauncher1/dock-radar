package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionEngine_AgePruning(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_retention_age_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	chunker, err := NewChunker(tempDir)
	if err != nil {
		t.Fatalf("failed to create chunker: %v", err)
	}

	engine := NewRetentionEngine(chunker)
	now := time.Now().UTC()

	// Create fake chunk files
	fileOld := filepath.Join(tempDir, "old.gz")
	fileNew := filepath.Join(tempDir, "new.gz")
	_ = os.WriteFile(fileOld, []byte("old-data"), 0644)
	_ = os.WriteFile(fileNew, []byte("new-data"), 0644)

	chunks := []*LogChunk{
		{
			ID:              "chunk-old",
			StartTime:       now.Add(-48 * time.Hour),
			EndTime:         now.Add(-40 * time.Hour),
			CompressedBytes: 8,
			LocalPath:       fileOld,
			S3Status:        S3StatusPending,
		},
		{
			ID:              "chunk-new",
			StartTime:       now.Add(-2 * time.Hour),
			EndTime:         now.Add(-1 * time.Hour),
			CompressedBytes: 8,
			LocalPath:       fileNew,
			S3Status:        S3StatusPending,
		},
	}

	cfg := RetentionConfig{
		MaxLocalChunks:      100,
		MaxLocalDiskBytes:   1000,
		LocalRetentionHours: 24, // 24h retention
	}

	res := engine.Enforce(chunks, cfg, now)
	if res.PrunedChunks != 1 {
		t.Fatalf("expected 1 chunk pruned, got %d", res.PrunedChunks)
	}
	if chunks[0].LocalPath != "" {
		t.Fatalf("expected old chunk local path to be cleared")
	}
	if chunks[1].LocalPath == "" {
		t.Fatalf("expected new chunk local path to remain intact")
	}

	if _, err := os.Stat(fileOld); !os.IsNotExist(err) {
		t.Fatalf("expected old file to be removed from disk")
	}
	if _, err := os.Stat(fileNew); err != nil {
		t.Fatalf("expected new file to still exist on disk")
	}
}

func TestRetentionEngine_OffloadPriorityEviction(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_retention_prio_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	chunker, err := NewChunker(tempDir)
	if err != nil {
		t.Fatalf("failed to create chunker: %v", err)
	}

	engine := NewRetentionEngine(chunker)
	now := time.Now().UTC()

	f1 := filepath.Join(tempDir, "c1.gz")
	f2 := filepath.Join(tempDir, "c2.gz")
	f3 := filepath.Join(tempDir, "c3.gz")
	_ = os.WriteFile(f1, []byte("data1"), 0644)
	_ = os.WriteFile(f2, []byte("data2"), 0644)
	_ = os.WriteFile(f3, []byte("data3"), 0644)

	// c1: older, but NOT offloaded yet
	// c2: middle, and IS offloaded
	// c3: newest, NOT offloaded
	chunks := []*LogChunk{
		{
			ID:              "c1",
			StartTime:       now.Add(-10 * time.Minute),
			EndTime:         now.Add(-9 * time.Minute),
			CompressedBytes: 5,
			LocalPath:       f1,
			S3Status:        S3StatusPending,
		},
		{
			ID:              "c2",
			StartTime:       now.Add(-8 * time.Minute),
			EndTime:         now.Add(-7 * time.Minute),
			CompressedBytes: 5,
			LocalPath:       f2,
			S3Status:        S3StatusOffloaded,
		},
		{
			ID:              "c3",
			StartTime:       now.Add(-6 * time.Minute),
			EndTime:         now.Add(-5 * time.Minute),
			CompressedBytes: 5,
			LocalPath:       f3,
			S3Status:        S3StatusPending,
		},
	}

	// Max 2 chunks allowed! We need to evict 1 chunk.
	// Since c2 is already offloaded to S3, it should be prioritized for eviction over c1!
	cfg := RetentionConfig{
		MaxLocalChunks:      2,
		MaxLocalDiskBytes:   100,
		LocalRetentionHours: 24,
	}

	res := engine.Enforce(chunks, cfg, now)
	if res.PrunedChunks != 1 {
		t.Fatalf("expected 1 chunk pruned, got %d", res.PrunedChunks)
	}
	if chunks[1].LocalPath != "" {
		t.Fatalf("expected offloaded chunk c2 to be pruned first")
	}
	if chunks[0].LocalPath == "" {
		t.Fatalf("expected pending chunk c1 to be preserved")
	}
}

func TestRetentionEngine_DiskBytesLimit(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_retention_bytes_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	chunker, err := NewChunker(tempDir)
	if err != nil {
		t.Fatalf("failed to create chunker: %v", err)
	}

	engine := NewRetentionEngine(chunker)
	now := time.Now().UTC()

	f1 := filepath.Join(tempDir, "b1.gz")
	f2 := filepath.Join(tempDir, "b2.gz")
	_ = os.WriteFile(f1, []byte("chunk-payload-1"), 0644)
	_ = os.WriteFile(f2, []byte("chunk-payload-2"), 0644)

	chunks := []*LogChunk{
		{
			ID:              "b1",
			StartTime:       now.Add(-5 * time.Minute),
			EndTime:         now.Add(-4 * time.Minute),
			CompressedBytes: 15,
			LocalPath:       f1,
			S3Status:        S3StatusOffloaded,
		},
		{
			ID:              "b2",
			StartTime:       now.Add(-3 * time.Minute),
			EndTime:         now.Add(-2 * time.Minute),
			CompressedBytes: 15,
			LocalPath:       f2,
			S3Status:        S3StatusPending,
		},
	}

	// Max disk bytes 20. Total is 30, so 1 must be evicted.
	cfg := RetentionConfig{
		MaxLocalChunks:      10,
		MaxLocalDiskBytes:   20,
		LocalRetentionHours: 24,
	}

	res := engine.Enforce(chunks, cfg, now)
	if res.PrunedChunks != 1 {
		t.Fatalf("expected 1 chunk pruned to fit disk limit, got %d", res.PrunedChunks)
	}
	if chunks[0].LocalPath != "" {
		t.Fatalf("expected b1 to be pruned")
	}
}

func TestRetentionEngine_CleanupOrphanedFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_retention_orphans_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	chunker, err := NewChunker(tempDir)
	if err != nil {
		t.Fatalf("failed to create chunker: %v", err)
	}

	engine := NewRetentionEngine(chunker)

	orphanFile := filepath.Join(tempDir, "stale-chunk.tmp")
	_ = os.WriteFile(orphanFile, []byte("stale-tmp"), 0644)

	// Set file mod time to 1 hour ago
	pastTime := time.Now().Add(-1 * time.Hour)
	_ = os.Chtimes(orphanFile, pastTime, pastTime)

	cleaned := engine.CleanupOrphanedFiles(tempDir, 10*time.Minute)
	if cleaned != 1 {
		t.Fatalf("expected 1 orphan file cleaned, got %d", cleaned)
	}

	if _, err := os.Stat(orphanFile); !os.IsNotExist(err) {
		t.Fatalf("expected orphan file to be deleted")
	}
}
