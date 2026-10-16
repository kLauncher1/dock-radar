package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/logs"
)

func TestChunker_CreateAndReadChunk(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_chunk_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	chunker, err := NewChunker(tempDir)
	if err != nil {
		t.Fatalf("failed to create chunker: %v", err)
	}

	now := time.Now().UTC()
	entries := []logs.LogEntry{
		{ID: "test-container-1", Stream: "stdout", Timestamp: now.Add(-2 * time.Second), Message: "Database connection established"},
		{ID: "test-container-1", Stream: "stdout", Timestamp: now.Add(-1 * time.Second), Message: "Listening on port 8080"},
		{ID: "test-container-1", Stream: "stderr", Timestamp: now, Message: "Cache miss warning for key user:100"},
	}

	chunk, compressed, err := chunker.CreateChunk("test-container-1", "all", entries)
	if err != nil {
		t.Fatalf("CreateChunk failed: %v", err)
	}

	if chunk.EntryCount != 3 {
		t.Fatalf("expected 3 entries, got %d", chunk.EntryCount)
	}
	if chunk.RawBytes <= 0 || chunk.CompressedBytes <= 0 {
		t.Fatalf("invalid byte counts: raw=%d compressed=%d", chunk.RawBytes, chunk.CompressedBytes)
	}
	if len(chunk.ChecksumSHA256) != 64 {
		t.Fatalf("expected 64-char hex SHA256, got %s", chunk.ChecksumSHA256)
	}
	if len(compressed) != int(chunk.CompressedBytes) {
		t.Fatalf("compressed byte slice length mismatch: %d vs %d", len(compressed), chunk.CompressedBytes)
	}

	// Verify file exists on disk
	if _, err := os.Stat(chunk.LocalPath); err != nil {
		t.Fatalf("chunk file does not exist on disk: %v", err)
	}

	// Read back entries
	readEntries, err := chunker.ReadChunk(chunk.LocalPath, chunk.ChecksumSHA256)
	if err != nil {
		t.Fatalf("ReadChunk failed: %v", err)
	}

	if len(readEntries) != 3 {
		t.Fatalf("expected 3 read entries, got %d", len(readEntries))
	}
	if readEntries[0].Message != entries[0].Message {
		t.Fatalf("first entry mismatch: expected %q, got %q", entries[0].Message, readEntries[0].Message)
	}

	// Corrupt file and test checksum mismatch
	corruptedData := append(compressed, []byte("tamper")...)
	corruptPath := filepath.Join(tempDir, "corrupted.gz")
	if err := os.WriteFile(corruptPath, corruptedData, 0644); err != nil {
		t.Fatalf("failed to write corrupted file: %v", err)
	}

	_, err = chunker.ReadChunk(corruptPath, chunk.ChecksumSHA256)
	if err == nil {
		t.Fatalf("expected checksum error on tampered chunk, got nil")
	}

	// Delete chunk file
	if err := chunker.DeleteChunkFile(chunk.LocalPath); err != nil {
		t.Fatalf("DeleteChunkFile failed: %v", err)
	}
	if _, err := os.Stat(chunk.LocalPath); !os.IsNotExist(err) {
		t.Fatalf("expected chunk file to be deleted")
	}
}

func TestChunker_EmptyEntries(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_chunk_empty_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	chunker, err := NewChunker(tempDir)
	if err != nil {
		t.Fatalf("failed to create chunker: %v", err)
	}

	_, _, err = chunker.CreateChunk("c1", "stdout", nil)
	if err != ErrEmptyEntries {
		t.Fatalf("expected ErrEmptyEntries, got %v", err)
	}
}

func TestValidateChunkID(t *testing.T) {
	valid := []string{
		"chunk-container1-1729000000-abcd-1",
		"chunk_web_app-123456",
		"system-1",
		"abc-DEF-123_456",
	}
	for _, id := range valid {
		if err := ValidateChunkID(id); err != nil {
			t.Errorf("expected valid chunk ID %q, got error: %v", id, err)
		}
	}

	invalid := []string{
		"",
		"../traversal",
		"..\\windows\\traversal",
		"chunk/subdir/file",
		"chunk\\subdir\\file",
		"chunk-123;rm -rf /",
		"chunk\"name",
		"chunk ID with spaces",
		"chunk\x00nullbyte",
	}
	for _, id := range invalid {
		if err := ValidateChunkID(id); err == nil {
			t.Errorf("expected error for invalid chunk ID %q, got nil", id)
		}
	}
}

func TestChunker_PathTraversalDefense(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dock_radar_chunk_traversal_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	chunker, err := NewChunker(tempDir)
	if err != nil {
		t.Fatalf("failed to create chunker: %v", err)
	}

	// Try reading file outside storageDir
	outsideFile := filepath.Join(os.TempDir(), "outside.gz")
	_ = os.WriteFile(outsideFile, []byte("fake"), 0644)
	defer os.Remove(outsideFile)

	_, err = chunker.ReadChunk(outsideFile, "")
	if err == nil {
		t.Fatal("expected error reading path outside storage root, got nil")
	}

	_, err = chunker.ReadChunkBytes(outsideFile)
	if err == nil {
		t.Fatal("expected error reading bytes for path outside storage root, got nil")
	}

	err = chunker.DeleteChunkFile(outsideFile)
	if err == nil {
		t.Fatal("expected error deleting path outside storage root, got nil")
	}
}

func TestEqualHex_ConstantTime(t *testing.T) {
	digestA := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	digestB := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	digestDiff := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	if !equalHex(digestA, digestB) {
		t.Fatal("expected identical digests to match")
	}
	if equalHex(digestA, digestDiff) {
		t.Fatal("expected different digests not to match")
	}
	if equalHex(digestA, "short") {
		t.Fatal("expected different lengths not to match")
	}
}
