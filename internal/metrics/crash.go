package metrics

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/crash"
)

// AppendCrashMetrics formats Distributed Core Dump & Crash Analysis telemetry into Prometheus exposition format.
func AppendCrashMetrics(builder *strings.Builder, status *crash.CrashStatus) {
	if status == nil {
		return
	}

	builder.WriteString("# HELP dock_radar_crash_enabled Whether the distributed core dump and crash analysis pipeline is enabled (1 or 0)\n")
	builder.WriteString("# TYPE dock_radar_crash_enabled gauge\n")
	enabledVal := 0
	if status.Enabled {
		enabledVal = 1
	}
	fmt.Fprintf(builder, "dock_radar_crash_enabled %d\n", enabledVal)

	builder.WriteString("# HELP dock_radar_crash_total_crashes Cumulative count of intercepted process crashes\n")
	builder.WriteString("# TYPE dock_radar_crash_total_crashes counter\n")
	fmt.Fprintf(builder, "dock_radar_crash_total_crashes %d\n", status.TotalCrashes)

	builder.WriteString("# HELP dock_radar_crash_unique_signatures Count of active distinct crash signature fingerprints\n")
	builder.WriteString("# TYPE dock_radar_crash_unique_signatures gauge\n")
	fmt.Fprintf(builder, "dock_radar_crash_unique_signatures %d\n", status.UniqueSignatures)

	builder.WriteString("# HELP dock_radar_crash_reports_stored Number of detailed crash diagnostic reports currently retained in memory\n")
	builder.WriteString("# TYPE dock_radar_crash_reports_stored gauge\n")
	fmt.Fprintf(builder, "dock_radar_crash_reports_stored %d\n", status.ReportsStored)

	builder.WriteString("# HELP dock_radar_crash_deduped_total Cumulative count of duplicate crashes absorbed by signature deduplication\n")
	builder.WriteString("# TYPE dock_radar_crash_deduped_total counter\n")
	fmt.Fprintf(builder, "dock_radar_crash_deduped_total %d\n", status.DedupedCount)

	if len(status.RootCauseCounts) > 0 {
		builder.WriteString("# HELP dock_radar_crash_root_cause_total Count of crashes categorized by root cause classification\n")
		builder.WriteString("# TYPE dock_radar_crash_root_cause_total counter\n")

		// Sort keys for deterministic output
		keys := make([]string, 0, len(status.RootCauseCounts))
		for k := range status.RootCauseCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			count := status.RootCauseCounts[k]
			fmt.Fprintf(builder, "dock_radar_crash_root_cause_total{category=\"%s\"} %d\n", escapeLabel(k), count)
		}
	}
	builder.WriteString("\n")
}
