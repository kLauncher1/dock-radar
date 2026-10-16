package storage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLogChunk_CompressionRatio(t *testing.T) {
	chunk := LogChunk{
		RawBytes:        1000,
		CompressedBytes: 250,
	}
	ratio := chunk.CompressionRatio()
	if ratio != 4.0 {
		t.Fatalf("expected ratio 4.0, got %f", ratio)
	}

	zeroChunk := LogChunk{RawBytes: 0, CompressedBytes: 0}
	if zeroChunk.CompressionRatio() != 1.0 {
		t.Fatalf("expected ratio 1.0 for zero chunk, got %f", zeroChunk.CompressionRatio())
	}
}

func TestS3Config_MaskedAndEnabled(t *testing.T) {
	cfg := S3Config{
		Endpoint:  "https://s3.us-east-1.amazonaws.com",
		Region:    "us-east-1",
		Bucket:    "my-logs",
		Prefix:    "dock-radar",
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	if !cfg.IsEnabled() {
		t.Fatalf("expected config to be enabled")
	}

	masked := cfg.Masked()
	if masked.SecretKey == cfg.SecretKey {
		t.Fatalf("secret key was not masked")
	}
	if !strings.HasSuffix(masked.SecretKey, "EKEY") {
		t.Fatalf("expected masked secret key to preserve last 4 chars, got %s", masked.SecretKey)
	}

	emptyCfg := S3Config{}
	if emptyCfg.IsEnabled() {
		t.Fatalf("expected empty config to be disabled")
	}
}

func TestRetentionConfig_Validate(t *testing.T) {
	r := RetentionConfig{
		MaxLocalChunks:        1,
		MaxLocalDiskBytes:     500,
		LocalRetentionHours:   0,
		ChunkSizeEntries:      2,
		ChunkFlushIntervalSec: 1,
	}

	if err := r.Validate(); err != nil {
		t.Fatalf("unexpected validate error: %v", err)
	}

	if r.MaxLocalChunks < 5 {
		t.Fatalf("expected MaxLocalChunks clamped to min 5, got %d", r.MaxLocalChunks)
	}
	if r.MaxLocalDiskBytes < 1024*1024 {
		t.Fatalf("expected MaxLocalDiskBytes clamped to min 1MB, got %d", r.MaxLocalDiskBytes)
	}
	if r.LocalRetentionHours < 1 {
		t.Fatalf("expected LocalRetentionHours clamped to min 1, got %d", r.LocalRetentionHours)
	}
	if r.ChunkSizeEntries < 10 {
		t.Fatalf("expected ChunkSizeEntries clamped to min 10, got %d", r.ChunkSizeEntries)
	}
	if r.ChunkFlushIntervalSec < 5 {
		t.Fatalf("expected ChunkFlushIntervalSec clamped to min 5, got %d", r.ChunkFlushIntervalSec)
	}
}

func TestStorageStatus_JSONRoundtrip(t *testing.T) {
	now := time.Now().UTC()
	status := StorageStatus{
		TotalChunks:          10,
		LocalChunks:          8,
		OffloadedChunks:      5,
		FailedChunks:         0,
		PendingChunks:        3,
		LocalDiskBytes:       40960,
		TotalRawBytes:        120000,
		TotalCompressedBytes: 30000,
		S3Enabled:            true,
		QueueDepth:           1,
		LastFlushTime:        now,
		LastOffloadTime:      now,
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded StorageStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.TotalChunks != status.TotalChunks || !decoded.S3Enabled {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", decoded, status)
	}
}
