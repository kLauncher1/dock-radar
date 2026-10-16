package storage

import (
	"errors"
	"strings"
	"time"
)

// S3 status constants representing the offload lifecycle of a chunk.
const (
	S3StatusPending    = "pending"
	S3StatusOffloading = "offloading"
	S3StatusOffloaded  = "offloaded"
	S3StatusFailed     = "failed"
	S3StatusDisabled   = "disabled"
)

// LogChunk encapsulates metadata and disk/cloud locator info for an immutable compressed batch of logs.
type LogChunk struct {
	ID              string    `json:"id"`
	ContainerID     string    `json:"container_id"`
	Stream          string    `json:"stream"`
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	EntryCount      int       `json:"entry_count"`
	RawBytes        int64     `json:"raw_bytes"`
	CompressedBytes int64     `json:"compressed_bytes"`
	ChecksumSHA256  string    `json:"checksum_sha256"`
	LocalPath       string    `json:"local_path,omitempty"`
	S3Key           string    `json:"s3_key,omitempty"`
	S3Status        string    `json:"s3_status"`
	StorageClass    string    `json:"storage_class,omitempty"`
}

// CompressionRatio computes space savings ratio (RawBytes / CompressedBytes).
func (c *LogChunk) CompressionRatio() float64 {
	if c.CompressedBytes <= 0 || c.RawBytes <= 0 {
		return 1.0
	}
	return float64(c.RawBytes) / float64(c.CompressedBytes)
}

// S3Config defines connection and authentication settings for S3-compatible object stores (MinIO, AWS S3, Cloudflare R2).
type S3Config struct {
	Endpoint       string `json:"endpoint"`
	Region         string `json:"region"`
	Bucket         string `json:"bucket"`
	Prefix         string `json:"prefix"`
	AccessKey      string `json:"access_key"`
	SecretKey      string `json:"secret_key,omitempty"`
	StorageClass   string `json:"storage_class,omitempty"`
	ForcePathStyle bool   `json:"force_path_style,omitempty"`
}

// DefaultS3Config returns standard configuration defaults.
func DefaultS3Config() S3Config {
	return S3Config{
		Endpoint:       "",
		Region:         "us-east-1",
		Bucket:         "",
		Prefix:         "dock-radar/logs",
		AccessKey:      "",
		SecretKey:      "",
		StorageClass:   "STANDARD",
		ForcePathStyle: true,
	}
}

// IsEnabled returns true if all mandatory credentials and bucket targets are specified.
func (c S3Config) IsEnabled() bool {
	return strings.TrimSpace(c.Endpoint) != "" &&
		strings.TrimSpace(c.Bucket) != "" &&
		strings.TrimSpace(c.AccessKey) != "" &&
		strings.TrimSpace(c.SecretKey) != ""
}

// Masked returns a safe duplicate of the configuration with the secret key masked.
func (c S3Config) Masked() S3Config {
	masked := c
	if masked.SecretKey != "" {
		if len(masked.SecretKey) > 4 {
			masked.SecretKey = strings.Repeat("*", len(masked.SecretKey)-4) + masked.SecretKey[len(masked.SecretKey)-4:]
		} else {
			masked.SecretKey = "********"
		}
	}
	return masked
}

// Validate checks for configuration sanity.
func (c S3Config) Validate() error {
	if !c.IsEnabled() {
		return nil // Disabled is a valid passive state
	}
	if strings.TrimSpace(c.Bucket) == "" {
		return errors.New("s3 bucket name cannot be empty")
	}
	if strings.TrimSpace(c.Region) == "" {
		return errors.New("s3 region cannot be empty")
	}
	return nil
}

// RetentionConfig specifies ephemeral local storage limits and rotation policies.
type RetentionConfig struct {
	MaxLocalChunks        int   `json:"max_local_chunks"`
	MaxLocalDiskBytes     int64 `json:"max_local_disk_bytes"`
	LocalRetentionHours   int   `json:"local_retention_hours"`
	PruneAfterOffload     bool  `json:"prune_after_offload"`
	ChunkSizeEntries      int   `json:"chunk_size_entries"`
	ChunkFlushIntervalSec int   `json:"chunk_flush_interval_sec"`
}

// DefaultRetentionConfig returns sensible operational defaults for low-overhead setups.
func DefaultRetentionConfig() RetentionConfig {
	return RetentionConfig{
		MaxLocalChunks:        100,
		MaxLocalDiskBytes:     100 * 1024 * 1024, // 100 MB
		LocalRetentionHours:   24,                // 24 hours
		PruneAfterOffload:     false,
		ChunkSizeEntries:      500,
		ChunkFlushIntervalSec: 60,
	}
}

// Validate clamps and enforces bounds on retention parameters.
func (r *RetentionConfig) Validate() error {
	if r.MaxLocalChunks < 5 {
		r.MaxLocalChunks = 5
	}
	if r.MaxLocalChunks > 10000 {
		r.MaxLocalChunks = 10000
	}

	if r.MaxLocalDiskBytes < 1*1024*1024 { // Min 1 MB
		r.MaxLocalDiskBytes = 1 * 1024 * 1024
	}
	if r.MaxLocalDiskBytes > 100*1024*1024*1024 { // Max 100 GB
		r.MaxLocalDiskBytes = 100 * 1024 * 1024 * 1024
	}

	if r.LocalRetentionHours < 1 {
		r.LocalRetentionHours = 1
	}
	if r.LocalRetentionHours > 8760 { // Max 1 year
		r.LocalRetentionHours = 8760
	}

	if r.ChunkSizeEntries < 10 {
		r.ChunkSizeEntries = 10
	}
	if r.ChunkSizeEntries > 10000 {
		r.ChunkSizeEntries = 10000
	}

	if r.ChunkFlushIntervalSec < 5 {
		r.ChunkFlushIntervalSec = 5
	}
	if r.ChunkFlushIntervalSec > 3600 {
		r.ChunkFlushIntervalSec = 3600
	}

	return nil
}

// StorageStatus provides real-time telemetry on chunk index, disk usage, and cloud offloader state.
type StorageStatus struct {
	TotalChunks          int       `json:"total_chunks"`
	LocalChunks          int       `json:"local_chunks"`
	OffloadedChunks      int       `json:"offloaded_chunks"`
	FailedChunks         int       `json:"failed_chunks"`
	PendingChunks        int       `json:"pending_chunks"`
	LocalDiskBytes       int64     `json:"local_disk_bytes"`
	TotalRawBytes        int64     `json:"total_raw_bytes"`
	TotalCompressedBytes int64     `json:"total_compressed_bytes"`
	S3Enabled            bool      `json:"s3_enabled"`
	QueueDepth           int       `json:"queue_depth"`
	LastFlushTime        time.Time `json:"last_flush_time"`
	LastOffloadTime      time.Time `json:"last_offload_time"`
	LastError            string    `json:"last_error,omitempty"`
}

// ChunkFilter defines query criteria for chunk searches.
type ChunkFilter struct {
	ContainerID string
	Stream      string
	S3Status    string
	Limit       int
	Offset      int
}
