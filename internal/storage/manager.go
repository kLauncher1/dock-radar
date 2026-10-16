package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kLauncher1/dock-radar/internal/logs"
)

var (
	// ErrChunkNotFound indicates the requested chunk ID does not exist in the index.
	ErrChunkNotFound = errors.New("log chunk not found")
	// ErrChunkFilePruned indicates the chunk metadata exists but the local file was pruned under retention policy.
	ErrChunkFilePruned = errors.New("log chunk file pruned from local disk under retention policy")
)

// Manager orchestrates log ingestion buffers, periodic chunk flushing, retention pruning, and S3 offload.
type Manager struct {
	mu            sync.RWMutex
	chunker       *Chunker
	retention     *RetentionEngine
	offloader     *Offloader
	s3Cfg         S3Config
	retCfg        RetentionConfig
	buffers       map[string][]logs.LogEntry
	chunks        []*LogChunk
	chunksIndex   map[string]*LogChunk
	lastFlushTime time.Time
	cancel        context.CancelFunc
	done          chan struct{}
}

// NewManager creates a StorageManager initializing underlying chunker, retention, and offloader engines.
func NewManager(storageDir string, s3Cfg S3Config, retCfg RetentionConfig) (*Manager, error) {
	if err := retCfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid retention config: %w", err)
	}

	chunker, err := NewChunker(storageDir)
	if err != nil {
		return nil, err
	}

	var s3Client *S3Client
	if s3Cfg.IsEnabled() {
		s3Client = NewS3Client(s3Cfg)
	}

	offloader := NewOffloader(s3Client, chunker, 1000)
	retention := NewRetentionEngine(chunker)

	mgr := &Manager{
		chunker:     chunker,
		retention:   retention,
		offloader:   offloader,
		s3Cfg:       s3Cfg,
		retCfg:      retCfg,
		buffers:     make(map[string][]logs.LogEntry),
		chunksIndex: make(map[string]*LogChunk),
	}

	// When chunk is offloaded and PruneAfterOffload is enabled, trigger immediate retention pass
	offloader.SetCompletionCallback(func(c *LogChunk) {
		mgr.mu.Lock()
		defer mgr.mu.Unlock()
		if mgr.retCfg.PruneAfterOffload {
			mgr.retention.Enforce(mgr.chunks, mgr.retCfg, time.Now().UTC())
		}
	})

	return mgr, nil
}

// Start boots background flush and retention ticker loops.
func (m *Manager) Start(parentCtx context.Context) {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parentCtx)
	m.cancel = cancel
	m.done = make(chan struct{})
	m.mu.Unlock()

	m.offloader.Start(ctx)
	go m.tickerLoop(ctx)
}

// Stop terminates background workers and flushes any pending entries.
func (m *Manager) Stop() {
	m.mu.Lock()
	cancel := m.cancel
	done := m.done
	m.cancel = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
		<-done
	}

	m.offloader.Stop()

	// Final flush
	_, _ = m.Flush()
}

// Ingest routes an incoming log entry into the active in-memory buffer.
func (m *Manager) Ingest(entry logs.LogEntry) {
	if entry.ID == "" {
		entry.ID = "system"
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	key := entry.ID

	m.mu.Lock()
	m.buffers[key] = append(m.buffers[key], entry)
	shouldFlush := len(m.buffers[key]) >= m.retCfg.ChunkSizeEntries
	m.mu.Unlock()

	if shouldFlush {
		_, _ = m.flushKey(key)
	}
}

// Flush immediately writes all accumulated buffer entries into disk chunks and queues them for S3 offload.
func (m *Manager) Flush() ([]*LogChunk, error) {
	m.mu.Lock()
	var keys []string
	for k, buf := range m.buffers {
		if len(buf) > 0 {
			keys = append(keys, k)
		}
	}
	m.mu.Unlock()

	var created []*LogChunk
	for _, k := range keys {
		chunk, err := m.flushKey(k)
		if err == nil && chunk != nil {
			created = append(created, chunk)
		}
	}

	return created, nil
}

func (m *Manager) flushKey(key string) (*LogChunk, error) {
	m.mu.Lock()
	entries := m.buffers[key]
	if len(entries) == 0 {
		m.mu.Unlock()
		return nil, nil
	}
	// Swap out buffer
	delete(m.buffers, key)
	retCfg := m.retCfg
	m.mu.Unlock()

	containerID := key
	stream := "all"
	if len(entries) > 0 && entries[0].Stream != "" {
		stream = entries[0].Stream
	}

	chunk, _, err := m.chunker.CreateChunk(containerID, stream, entries)
	if err != nil {
		// Restore buffer on failure
		m.mu.Lock()
		m.buffers[key] = append(entries, m.buffers[key]...)
		m.mu.Unlock()
		return nil, err
	}

	m.mu.Lock()
	m.chunks = append(m.chunks, chunk)
	m.chunksIndex[chunk.ID] = chunk
	m.lastFlushTime = time.Now().UTC()
	m.mu.Unlock()

	// Enqueue to offloader
	m.offloader.Enqueue(chunk)

	// Run retention enforcement
	m.mu.Lock()
	m.retention.Enforce(m.chunks, retCfg, time.Now().UTC())
	m.mu.Unlock()

	return chunk, nil
}

// ListChunks returns paginated and filtered log chunks ordered newest to oldest.
func (m *Manager) ListChunks(filter ChunkFilter) ([]*LogChunk, int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []*LogChunk
	containerFilter := strings.ToLower(strings.TrimSpace(filter.ContainerID))
	streamFilter := strings.ToLower(strings.TrimSpace(filter.Stream))
	statusFilter := strings.ToLower(strings.TrimSpace(filter.S3Status))

	for i := len(m.chunks) - 1; i >= 0; i-- {
		c := m.chunks[i]
		if containerFilter != "" && !strings.Contains(strings.ToLower(c.ContainerID), containerFilter) {
			continue
		}
		if streamFilter != "" && streamFilter != "all" && !strings.EqualFold(c.Stream, streamFilter) {
			continue
		}
		if statusFilter != "" && !strings.EqualFold(c.S3Status, statusFilter) {
			continue
		}
		matched = append(matched, c)
	}

	total := len(matched)
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []*LogChunk{}, total
	}

	end := total
	if filter.Limit > 0 && offset+filter.Limit < total {
		end = offset + filter.Limit
	}

	return matched[offset:end], total
}

// GetChunk returns metadata for a single chunk by ID.
func (m *Manager) GetChunk(id string) (*LogChunk, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	chunk, ok := m.chunksIndex[id]
	if !ok {
		return nil, ErrChunkNotFound
	}
	return chunk, nil
}

// ReadChunkEntries decompresses and returns the slice of log entries inside a chunk.
func (m *Manager) ReadChunkEntries(id string) ([]logs.LogEntry, error) {
	chunk, err := m.GetChunk(id)
	if err != nil {
		return nil, err
	}

	if chunk.LocalPath == "" {
		return nil, ErrChunkFilePruned
	}

	return m.chunker.ReadChunk(chunk.LocalPath, chunk.ChecksumSHA256)
}

// ReadChunkBytes returns the raw compressed bytes for direct download.
func (m *Manager) ReadChunkBytes(id string) ([]byte, error) {
	chunk, err := m.GetChunk(id)
	if err != nil {
		return nil, err
	}

	if chunk.LocalPath == "" {
		return nil, ErrChunkFilePruned
	}

	return m.chunker.ReadChunkBytes(chunk.LocalPath)
}

// GetS3Config returns a masked copy of the active S3 configuration.
func (m *Manager) GetS3Config() S3Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.s3Cfg.Masked()
}

// GetRetentionConfig returns the active local retention settings.
func (m *Manager) GetRetentionConfig() RetentionConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.retCfg
}

// UpdateConfig modifies S3 and retention parameters dynamically.
func (m *Manager) UpdateConfig(s3 S3Config, ret RetentionConfig) error {
	if err := ret.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// If secret key was left masked, retain existing secret key
	if strings.Contains(s3.SecretKey, "*") && m.s3Cfg.SecretKey != "" {
		s3.SecretKey = m.s3Cfg.SecretKey
	}

	m.s3Cfg = s3
	m.retCfg = ret

	var client *S3Client
	if s3.IsEnabled() {
		client = NewS3Client(s3)
	}
	m.offloader.UpdateClient(client)

	return nil
}

// TestS3Connection evaluates bucket accessibility using provided or stored settings.
func (m *Manager) TestS3Connection(ctx context.Context, cfg S3Config) error {
	if strings.Contains(cfg.SecretKey, "*") {
		m.mu.RLock()
		cfg.SecretKey = m.s3Cfg.SecretKey
		m.mu.RUnlock()
	}

	if !cfg.IsEnabled() {
		return errors.New("s3 configuration is missing required credentials or bucket")
	}

	client := NewS3Client(cfg)
	return client.HeadBucket(ctx)
}

// Status compiles complete operational metrics across memory, disk, and S3 offloader.
func (m *Manager) Status() StorageStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := StorageStatus{
		TotalChunks:   len(m.chunks),
		S3Enabled:     m.s3Cfg.IsEnabled(),
		QueueDepth:    m.offloader.QueueDepth(),
		LastFlushTime: m.lastFlushTime,
	}

	offloaded, failed, lastOffload, lastErr := m.offloader.Stats()
	status.OffloadedChunks = int(offloaded)
	status.FailedChunks = int(failed)
	status.LastOffloadTime = lastOffload
	status.LastError = lastErr

	for _, c := range m.chunks {
		if c.LocalPath != "" {
			status.LocalChunks++
			status.LocalDiskBytes += c.CompressedBytes
		}
		status.TotalRawBytes += c.RawBytes
		status.TotalCompressedBytes += c.CompressedBytes

		if c.S3Status == S3StatusPending || c.S3Status == S3StatusOffloading {
			status.PendingChunks++
		}
	}

	return status
}

func (m *Manager) tickerLoop(ctx context.Context) {
	defer close(m.done)

	flushInterval := time.Duration(m.retCfg.ChunkFlushIntervalSec) * time.Second
	if flushInterval < 5*time.Second {
		flushInterval = 5 * time.Second
	}
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	retentionTicker := time.NewTicker(15 * time.Second)
	defer retentionTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-flushTicker.C:
			_, _ = m.Flush()
		case <-retentionTicker.C:
			m.mu.Lock()
			m.retention.Enforce(m.chunks, m.retCfg, time.Now().UTC())
			m.retention.CleanupOrphanedFiles(m.chunker.StorageDir(), 10*time.Minute)
			m.mu.Unlock()
		}
	}
}
