package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestOffloader_DisabledS3Fallback(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_offload_disabled_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	chunker, err := NewChunker(tempDir)
	if err != nil {
		t.Fatalf("failed to create chunker: %v", err)
	}

	offloader := NewOffloader(nil, chunker, 10)
	chunk := &LogChunk{ID: "chunk-test-1", S3Status: S3StatusPending}

	queued := offloader.Enqueue(chunk)
	if queued {
		t.Fatalf("expected Enqueue to return false when S3 disabled")
	}
	if chunk.S3Status != S3StatusDisabled {
		t.Fatalf("expected status %s, got %s", S3StatusDisabled, chunk.S3Status)
	}
}

func TestOffloader_UploadLifecycle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_offload_life_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	chunker, err := NewChunker(tempDir)
	if err != nil {
		t.Fatalf("failed to create chunker: %v", err)
	}

	var uploadCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&uploadCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := S3Config{
		Endpoint:       server.URL,
		Bucket:         "test-bucket",
		Prefix:         "logs",
		AccessKey:      "KEY",
		SecretKey:      "SECRET",
		ForcePathStyle: true,
	}
	client := NewS3Client(cfg)
	offloader := NewOffloader(client, chunker, 10)

	var callbackInvoked bool
	offloader.SetCompletionCallback(func(c *LogChunk) {
		callbackInvoked = true
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	offloader.Start(ctx)
	defer offloader.Stop()

	// Write dummy chunk file
	filePath := filepath.Join(tempDir, "chunk-1.gz")
	_ = os.WriteFile(filePath, []byte("compressed-payload"), 0644)

	chunk := &LogChunk{
		ID:        "chunk-1",
		LocalPath: filePath,
	}

	queued := offloader.Enqueue(chunk)
	if !queued {
		t.Fatalf("expected chunk to be queued")
	}

	// Wait for worker to process
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if chunk.S3Status == S3StatusOffloaded {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if chunk.S3Status != S3StatusOffloaded {
		t.Fatalf("expected chunk status offloaded, got %s", chunk.S3Status)
	}
	if !callbackInvoked {
		t.Fatalf("expected completion callback to be called")
	}

	offloaded, failed, _, _ := offloader.Stats()
	if offloaded != 1 || failed != 0 {
		t.Fatalf("expected stats offloaded=1, failed=0, got offloaded=%d, failed=%d", offloaded, failed)
	}
}

func TestOffloader_RetryOnFailure(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_offload_retry_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	chunker, err := NewChunker(tempDir)
	if err != nil {
		t.Fatalf("failed to create chunker: %v", err)
	}

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := S3Config{
		Endpoint:       server.URL,
		Bucket:         "test-bucket",
		AccessKey:      "KEY",
		SecretKey:      "SECRET",
		ForcePathStyle: true,
	}
	client := NewS3Client(cfg)
	offloader := NewOffloader(client, chunker, 10)
	offloader.baseBackoff = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	offloader.Start(ctx)
	defer offloader.Stop()

	filePath := filepath.Join(tempDir, "chunk-retry.gz")
	_ = os.WriteFile(filePath, []byte("retry-payload"), 0644)

	chunk := &LogChunk{
		ID:        "chunk-retry",
		LocalPath: filePath,
	}

	offloader.Enqueue(chunk)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if chunk.S3Status == S3StatusOffloaded {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if chunk.S3Status != S3StatusOffloaded {
		t.Fatalf("expected chunk to succeed after retry, got %s", chunk.S3Status)
	}
	if atomic.LoadInt32(&attempts) < 2 {
		t.Fatalf("expected at least 2 attempts, got %d", atomic.LoadInt32(&attempts))
	}
}
