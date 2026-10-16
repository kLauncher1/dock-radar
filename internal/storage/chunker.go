package storage

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kLauncher1/dock-radar/internal/logs"
)

var (
	// ErrEmptyEntries indicates an attempt to produce a chunk with zero entries.
	ErrEmptyEntries = errors.New("cannot create chunk from empty entries list")
	// ErrChecksumMismatch indicates corrupted data on disk or in transit.
	ErrChecksumMismatch = errors.New("chunk sha256 checksum verification failed")
	// ErrInvalidChunkID indicates a malformed or path traversal chunk ID.
	ErrInvalidChunkID = errors.New("invalid chunk id format")
	// nonAlphanumericRegexp sanitizes container IDs for safe filenames.
	nonAlphanumericRegexp = regexp.MustCompile(`[^a-zA-Z0-9_\-]`)
	// validChunkIDRegexp validates that chunk IDs strictly contain safe characters.
	validChunkIDRegexp = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)
)

var chunkSeq uint64

// Chunker handles gzip compression, SHA-256 verification, and atomic disk persistence for log chunks.
type Chunker struct {
	storageDir string
}

// NewChunker initializes a log chunker targeted at the given base directory.
func NewChunker(storageDir string) (*Chunker, error) {
	if storageDir == "" {
		storageDir = filepath.Join("data", "logs")
	}
	absPath, err := filepath.Abs(storageDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve storage directory absolute path: %w", err)
	}

	if err := os.MkdirAll(absPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log storage directory %s: %w", absPath, err)
	}

	return &Chunker{
		storageDir: absPath,
	}, nil
}

// StorageDir returns the resolved directory path.
func (c *Chunker) StorageDir() string {
	return c.storageDir
}

// CreateChunk serializes and gzip-compresses the provided log entries, writing them atomically to disk.
func (c *Chunker) CreateChunk(containerID, stream string, entries []logs.LogEntry) (*LogChunk, []byte, error) {
	if len(entries) == 0 {
		return nil, nil, ErrEmptyEntries
	}

	rawJSON, err := json.Marshal(entries)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize entries to json: %w", err)
	}
	rawBytes := int64(len(rawJSON))

	var compressedBuf bytes.Buffer
	gzWriter, err := gzip.NewWriterLevel(&compressedBuf, gzip.BestSpeed)
	if err != nil {
		gzWriter = gzip.NewWriter(&compressedBuf)
	}
	if _, err := gzWriter.Write(rawJSON); err != nil {
		_ = gzWriter.Close()
		return nil, nil, fmt.Errorf("gzip compression failed: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return nil, nil, fmt.Errorf("gzip close failed: %w", err)
	}

	compressedData := compressedBuf.Bytes()
	compressedBytes := int64(len(compressedData))

	hash := sha256.Sum256(compressedData)
	checksumHex := hex.EncodeToString(hash[:])

	cleanContainerID := nonAlphanumericRegexp.ReplaceAllString(containerID, "_")
	if cleanContainerID == "" {
		cleanContainerID = "system"
	}
	if len(cleanContainerID) > 24 {
		cleanContainerID = cleanContainerID[:24]
	}

	now := time.Now().UTC()
	seq := atomic.AddUint64(&chunkSeq, 1)
	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)
	chunkID := fmt.Sprintf("chunk-%s-%d-%04x-%d", cleanContainerID, now.Unix(), randBytes, seq)

	finalFilename := chunkID + ".gz"
	finalPath := filepath.Join(c.storageDir, finalFilename)
	tmpPath := filepath.Join(c.storageDir, chunkID+".tmp")

	// Atomic write: write to temp file, sync, then rename
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open temp chunk file: %w", err)
	}

	if _, err := tmpFile.Write(compressedData); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return nil, nil, fmt.Errorf("failed to write compressed data: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return nil, nil, fmt.Errorf("failed to sync temp file: %w", err)
	}
	_ = tmpFile.Close()

	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, nil, fmt.Errorf("atomic rename failed: %w", err)
	}

	startTime := entries[0].Timestamp
	endTime := entries[len(entries)-1].Timestamp
	if startTime.IsZero() {
		startTime = now
	}
	if endTime.IsZero() {
		endTime = now
	}

	chunk := &LogChunk{
		ID:              chunkID,
		ContainerID:     containerID,
		Stream:          stream,
		StartTime:       startTime,
		EndTime:         endTime,
		EntryCount:      len(entries),
		RawBytes:        rawBytes,
		CompressedBytes: compressedBytes,
		ChecksumSHA256:  checksumHex,
		LocalPath:       finalPath,
		S3Status:        S3StatusPending,
	}

	return chunk, compressedData, nil
}

// ValidateChunkID checks whether a chunk ID conforms to the strict alphanumeric/dash/underscore format.
func ValidateChunkID(id string) error {
	if id == "" {
		return errors.New("chunk ID cannot be empty")
	}
	if len(id) > 128 {
		return errors.New("chunk ID exceeds maximum length of 128 characters")
	}
	if strings.Contains(id, "..") || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return fmt.Errorf("%w: path traversal sequences detected", ErrInvalidChunkID)
	}
	if !validChunkIDRegexp.MatchString(id) {
		return fmt.Errorf("%w: must contain only alphanumeric characters, underscores, or hyphens", ErrInvalidChunkID)
	}
	return nil
}

func (c *Chunker) validateWithinStorage(filePath string) error {
	if filePath == "" {
		return nil
	}
	cleanPath := filepath.Clean(filePath)
	rel, err := filepath.Rel(c.storageDir, cleanPath)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return fmt.Errorf("chunk file path escapes storage directory root: %s", filePath)
	}
	return nil
}

// ReadChunk reads a compressed chunk file from disk, verifies its SHA-256 checksum, and decompresses it into LogEntry structs.
func (c *Chunker) ReadChunk(filePath string, expectedChecksum string) ([]logs.LogEntry, error) {
	if err := c.validateWithinStorage(filePath); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read chunk file %s: %w", filePath, err)
	}

	if expectedChecksum != "" {
		hash := sha256.Sum256(data)
		calcHex := hex.EncodeToString(hash[:])
		if !equalHex(calcHex, expectedChecksum) {
			return nil, fmt.Errorf("%w: expected %s, calculated %s", ErrChecksumMismatch, expectedChecksum, calcHex)
		}
	}

	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip reader error: %w", err)
	}
	defer gzReader.Close()

	decompressed, err := io.ReadAll(gzReader)
	if err != nil {
		return nil, fmt.Errorf("gzip read decompression error: %w", err)
	}

	var entries []logs.LogEntry
	if err := json.Unmarshal(decompressed, &entries); err != nil {
		return nil, fmt.Errorf("failed to deserialize json entries: %w", err)
	}

	return entries, nil
}

// ReadChunkBytes reads the raw compressed bytes of a chunk file.
func (c *Chunker) ReadChunkBytes(filePath string) ([]byte, error) {
	if err := c.validateWithinStorage(filePath); err != nil {
		return nil, err
	}
	return os.ReadFile(filePath)
}

// DeleteChunkFile removes a chunk from the local filesystem.
func (c *Chunker) DeleteChunkFile(filePath string) error {
	if filePath == "" {
		return nil
	}
	if err := c.validateWithinStorage(filePath); err != nil {
		return err
	}
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func equalHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
