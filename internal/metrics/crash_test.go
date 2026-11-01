package metrics

import (
	"strings"
	"testing"

	"github.com/kLauncher1/dock-radar/internal/crash"
)

func TestAppendCrashMetrics(t *testing.T) {
	st := &crash.CrashStatus{
		Enabled:          true,
		TotalCrashes:     42,
		UniqueSignatures: 5,
		ReportsStored:    12,
		DedupedCount:     30,
		RootCauseCounts: map[string]int{
			"null_pointer_dereference": 25,
			"assertion_failure":        10,
			"oom_killed":               7,
		},
	}

	var sb strings.Builder
	AppendCrashMetrics(&sb, st)

	out := sb.String()
	expectedMetrics := []string{
		"dock_radar_crash_enabled 1",
		"dock_radar_crash_total_crashes 42",
		"dock_radar_crash_unique_signatures 5",
		"dock_radar_crash_reports_stored 12",
		"dock_radar_crash_deduped_total 30",
		`dock_radar_crash_root_cause_total{category="null_pointer_dereference"} 25`,
		`dock_radar_crash_root_cause_total{category="assertion_failure"} 10`,
		`dock_radar_crash_root_cause_total{category="oom_killed"} 7`,
	}

	for _, m := range expectedMetrics {
		if !strings.Contains(out, m) {
			t.Errorf("missing expected metric line: %q in output:\n%s", m, out)
		}
	}

	// Nil guard
	var sbNil strings.Builder
	AppendCrashMetrics(&sbNil, nil)
	if sbNil.Len() != 0 {
		t.Errorf("expected empty string on nil status")
	}
}
