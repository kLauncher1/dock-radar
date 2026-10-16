package metrics

import (
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/storage"
)

func TestAppendStorageMetrics(t *testing.T) {
	var b strings.Builder

	// Test nil safety
	AppendStorageMetrics(&b, nil)
	if b.Len() != 0 {
		t.Fatalf("expected empty builder for nil status")
	}

	status := &storage.StorageStatus{
		TotalChunks:     15,
		LocalDiskBytes:  409600,
		OffloadedChunks: 10,
		FailedChunks:    1,
		QueueDepth:      2,
		S3Enabled:       true,
	}

	AppendStorageMetrics(&b, status)
	output := b.String()

	expectedGauges := []string{
		"dock_radar_log_storage_chunks_total 15",
		"dock_radar_log_storage_disk_bytes 409600",
		"dock_radar_log_storage_offloaded_total 10",
		"dock_radar_log_storage_offload_failed_total 1",
		"dock_radar_log_storage_queue_depth 2",
		"dock_radar_log_storage_s3_enabled 1",
	}

	for _, expected := range expectedGauges {
		if !strings.Contains(output, expected) {
			t.Fatalf("missing expected metric in output: %s\nGot:\n%s", expected, output)
		}
	}
}
