package storage

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// RetentionEngine enforces ephemeral local disk quotas, age expiration, and offload-priority pruning.
type RetentionEngine struct {
	mu      sync.Mutex
	chunker *Chunker
}

// PruneResult summarizes the action taken during a retention enforcement cycle.
type PruneResult struct {
	PrunedChunks int
	BytesFreed   int64
	PrunedIDs    []string
}

// NewRetentionEngine constructs a retention engine with the provided chunker.
func NewRetentionEngine(chunker *Chunker) *RetentionEngine {
	return &RetentionEngine{
		chunker: chunker,
	}
}

// Enforce evaluates all active chunks against retention policies and prunes files as necessary.
func (r *RetentionEngine) Enforce(chunks []*LogChunk, cfg RetentionConfig, now time.Time) PruneResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	if now.IsZero() {
		now = time.Now().UTC()
	}

	result := PruneResult{}
	if len(chunks) == 0 {
		return result
	}

	// 1. Offload-priority immediate pruning if configured
	if cfg.PruneAfterOffload {
		for _, chunk := range chunks {
			if chunk.LocalPath != "" && chunk.S3Status == S3StatusOffloaded {
				if r.pruneChunkFile(chunk) {
					result.PrunedChunks++
					result.BytesFreed += chunk.CompressedBytes
					result.PrunedIDs = append(result.PrunedIDs, chunk.ID)
				}
			}
		}
	}

	// 2. Age-based expiration pruning
	ageThreshold := now.Add(-time.Duration(cfg.LocalRetentionHours) * time.Hour)
	for _, chunk := range chunks {
		if chunk.LocalPath != "" && chunk.EndTime.Before(ageThreshold) {
			if r.pruneChunkFile(chunk) {
				result.PrunedChunks++
				result.BytesFreed += chunk.CompressedBytes
				result.PrunedIDs = append(result.PrunedIDs, chunk.ID)
			}
		}
	}

	// Collect remaining local chunks
	var localChunks []*LogChunk
	var totalDiskBytes int64
	for _, chunk := range chunks {
		if chunk.LocalPath != "" {
			localChunks = append(localChunks, chunk)
			totalDiskBytes += chunk.CompressedBytes
		}
	}

	// Sort oldest first (by StartTime, then EndTime)
	sort.Slice(localChunks, func(i, j int) bool {
		if localChunks[i].StartTime.Equal(localChunks[j].StartTime) {
			return localChunks[i].EndTime.Before(localChunks[j].EndTime)
		}
		return localChunks[i].StartTime.Before(localChunks[j].StartTime)
	})

	// 3. MaxLocalChunks cap enforcement
	if len(localChunks) > cfg.MaxLocalChunks {
		excess := len(localChunks) - cfg.MaxLocalChunks

		// Pass A: Prune offloaded chunks first
		for _, chunk := range localChunks {
			if excess <= 0 {
				break
			}
			if chunk.LocalPath != "" && chunk.S3Status == S3StatusOffloaded {
				if r.pruneChunkFile(chunk) {
					result.PrunedChunks++
					result.BytesFreed += chunk.CompressedBytes
					result.PrunedIDs = append(result.PrunedIDs, chunk.ID)
					totalDiskBytes -= chunk.CompressedBytes
					excess--
				}
			}
		}

		// Pass B: Prune remaining oldest chunks if still over limit
		if excess > 0 {
			for _, chunk := range localChunks {
				if excess <= 0 {
					break
				}
				if chunk.LocalPath != "" {
					if r.pruneChunkFile(chunk) {
						result.PrunedChunks++
						result.BytesFreed += chunk.CompressedBytes
						result.PrunedIDs = append(result.PrunedIDs, chunk.ID)
						totalDiskBytes -= chunk.CompressedBytes
						excess--
					}
				}
			}
		}
	}

	// 4. MaxLocalDiskBytes cap enforcement
	if totalDiskBytes > cfg.MaxLocalDiskBytes {
		// Pass A: Prune offloaded chunks first
		for _, chunk := range localChunks {
			if totalDiskBytes <= cfg.MaxLocalDiskBytes {
				break
			}
			if chunk.LocalPath != "" && chunk.S3Status == S3StatusOffloaded {
				if r.pruneChunkFile(chunk) {
					result.PrunedChunks++
					result.BytesFreed += chunk.CompressedBytes
					result.PrunedIDs = append(result.PrunedIDs, chunk.ID)
					totalDiskBytes -= chunk.CompressedBytes
				}
			}
		}

		// Pass B: Prune remaining oldest chunks
		if totalDiskBytes > cfg.MaxLocalDiskBytes {
			for _, chunk := range localChunks {
				if totalDiskBytes <= cfg.MaxLocalDiskBytes {
					break
				}
				if chunk.LocalPath != "" {
					if r.pruneChunkFile(chunk) {
						result.PrunedChunks++
						result.BytesFreed += chunk.CompressedBytes
						result.PrunedIDs = append(result.PrunedIDs, chunk.ID)
						totalDiskBytes -= chunk.CompressedBytes
					}
				}
			}
		}
	}

	return result
}

// CleanupOrphanedFiles cleans up stale temporary files left behind from crashes or interrupted writes.
func (r *RetentionEngine) CleanupOrphanedFiles(storageDir string, maxAge time.Duration) int {
	if storageDir == "" {
		return 0
	}

	entries, err := os.ReadDir(storageDir)
	if err != nil {
		return 0
	}

	now := time.Now()
	cleaned := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".tmp") {
			fullPath := filepath.Join(storageDir, name)
			info, err := entry.Info()
			if err == nil && now.Sub(info.ModTime()) > maxAge {
				if err := os.Remove(fullPath); err == nil {
					cleaned++
				}
			}
		}
	}
	return cleaned
}

func (r *RetentionEngine) pruneChunkFile(chunk *LogChunk) bool {
	if chunk.LocalPath == "" {
		return false
	}
	err := r.chunker.DeleteChunkFile(chunk.LocalPath)
	chunk.LocalPath = ""
	return err == nil
}
