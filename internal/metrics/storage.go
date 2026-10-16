package metrics

import (
	"fmt"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/storage"
)

// AppendStorageMetrics formats ephemeral log storage and S3 offloader telemetry into standard Prometheus text format.
func AppendStorageMetrics(b *strings.Builder, status *storage.StorageStatus) {
	if status == nil {
		return
	}

	b.WriteString("# HELP dock_radar_log_storage_chunks_total Total number of compressed log chunks tracked in local catalog.\n")
	b.WriteString("# TYPE dock_radar_log_storage_chunks_total gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_log_storage_chunks_total %d\n\n", status.TotalChunks))

	b.WriteString("# HELP dock_radar_log_storage_disk_bytes Total bytes consumed by compressed log chunks on local disk.\n")
	b.WriteString("# TYPE dock_radar_log_storage_disk_bytes gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_log_storage_disk_bytes %d\n\n", status.LocalDiskBytes))

	b.WriteString("# HELP dock_radar_log_storage_offloaded_total Cumulative number of log chunks successfully offloaded to S3.\n")
	b.WriteString("# TYPE dock_radar_log_storage_offloaded_total counter\n")
	b.WriteString(fmt.Sprintf("dock_radar_log_storage_offloaded_total %d\n\n", status.OffloadedChunks))

	b.WriteString("# HELP dock_radar_log_storage_offload_failed_total Cumulative number of log chunks that failed S3 offload attempts.\n")
	b.WriteString("# TYPE dock_radar_log_storage_offload_failed_total counter\n")
	b.WriteString(fmt.Sprintf("dock_radar_log_storage_offload_failed_total %d\n\n", status.FailedChunks))

	b.WriteString("# HELP dock_radar_log_storage_queue_depth Current depth of the asynchronous S3 offload worker queue.\n")
	b.WriteString("# TYPE dock_radar_log_storage_queue_depth gauge\n")
	b.WriteString(fmt.Sprintf("dock_radar_log_storage_queue_depth %d\n\n", status.QueueDepth))

	b.WriteString("# HELP dock_radar_log_storage_s3_enabled Whether S3 object store offloader is configured and active (1) or disabled (0).\n")
	b.WriteString("# TYPE dock_radar_log_storage_s3_enabled gauge\n")
	s3Val := 0
	if status.S3Enabled {
		s3Val = 1
	}
	b.WriteString(fmt.Sprintf("dock_radar_log_storage_s3_enabled %d\n\n", s3Val))
}
