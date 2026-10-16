package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/logs"
)

func TestStorageManager_IngestAndFlush(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_mgr_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	s3Cfg := DefaultS3Config()
	retCfg := DefaultRetentionConfig()
	retCfg.ChunkSizeEntries = 10 // Minimum allowed chunk size

	mgr, err := NewManager(tempDir, s3Cfg, retCfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	defer mgr.Stop()

	// Ingest 9 entries (should stay buffered)
	for i := 0; i < 9; i++ {
		mgr.Ingest(logs.LogEntry{
			ID:        "web-svc",
			Stream:    "stdout",
			Timestamp: time.Now().UTC(),
			Message:   "GET /index.html 200 OK",
		})
	}

	chunks, total := mgr.ListChunks(ChunkFilter{})
	if total != 0 {
		t.Fatalf("expected 0 chunks before threshold, got %d", total)
	}

	// Ingest 10th entry (should trigger auto flush!)
	mgr.Ingest(logs.LogEntry{
		ID:        "web-svc",
		Stream:    "stdout",
		Timestamp: time.Now().UTC(),
		Message:   "GET /styles.css 200 OK",
	})

	chunks, total = mgr.ListChunks(ChunkFilter{ContainerID: "web-svc"})
	if total != 1 || len(chunks) != 1 {
		t.Fatalf("expected 1 chunk created after 10th entry, got total=%d len=%d", total, len(chunks))
	}

	chunk := chunks[0]
	if chunk.EntryCount != 10 {
		t.Fatalf("expected 10 entries in chunk, got %d", chunk.EntryCount)
	}

	// Read entries back
	entries, err := mgr.ReadChunkEntries(chunk.ID)
	if err != nil {
		t.Fatalf("ReadChunkEntries failed: %v", err)
	}
	if len(entries) != 10 {
		t.Fatalf("expected 10 entries read back, got %d", len(entries))
	}

	// Read raw bytes
	rawBytes, err := mgr.ReadChunkBytes(chunk.ID)
	if err != nil {
		t.Fatalf("ReadChunkBytes failed: %v", err)
	}
	if len(rawBytes) != int(chunk.CompressedBytes) {
		t.Fatalf("raw bytes mismatch: %d vs %d", len(rawBytes), chunk.CompressedBytes)
	}

	// Manual flush test
	mgr.Ingest(logs.LogEntry{
		ID:        "db-svc",
		Stream:    "stderr",
		Timestamp: time.Now().UTC(),
		Message:   "slow query detected",
	})
	flushed, err := mgr.Flush()
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if len(flushed) != 1 {
		t.Fatalf("expected 1 manually flushed chunk, got %d", len(flushed))
	}

	status := mgr.Status()
	if status.TotalChunks != 2 {
		t.Fatalf("expected TotalChunks=2, got %d", status.TotalChunks)
	}
	if status.LocalChunks != 2 {
		t.Fatalf("expected LocalChunks=2, got %d", status.LocalChunks)
	}
	if status.TotalRawBytes <= 0 || status.TotalCompressedBytes <= 0 {
		t.Fatalf("invalid byte totals in status")
	}
}

func TestStorageManager_ConfigAndUpdate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_mgr_cfg_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	s3Cfg := DefaultS3Config()
	retCfg := DefaultRetentionConfig()

	mgr, err := NewManager(tempDir, s3Cfg, retCfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	newS3 := S3Config{
		Endpoint:  "https://s3.us-west-2.amazonaws.com",
		Region:    "us-west-2",
		Bucket:    "my-custom-bucket",
		AccessKey: "AKIAUPDATED",
		SecretKey: "SECRETUPDATEDKEY",
	}
	newRet := RetentionConfig{
		MaxLocalChunks:        50,
		MaxLocalDiskBytes:     50 * 1024 * 1024,
		LocalRetentionHours:   12,
		ChunkSizeEntries:      200,
		ChunkFlushIntervalSec: 30,
	}

	err = mgr.UpdateConfig(newS3, newRet)
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	masked := mgr.GetS3Config()
	if masked.Bucket != "my-custom-bucket" || !mgr.Status().S3Enabled {
		t.Fatalf("config update not reflected in manager")
	}
	if masked.SecretKey == "SECRETUPDATEDKEY" {
		t.Fatalf("expected secret key to be masked")
	}
}

func TestStorageManager_TestS3Connection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_mgr_s3test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	mgr, err := NewManager(tempDir, DefaultS3Config(), DefaultRetentionConfig())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	testCfg := S3Config{
		Endpoint:       server.URL,
		Bucket:         "radar-test",
		AccessKey:      "TESTKEY",
		SecretKey:      "TESTSECRET",
		ForcePathStyle: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = mgr.TestS3Connection(ctx, testCfg)
	if err != nil {
		t.Fatalf("TestS3Connection failed: %v", err)
	}
}
