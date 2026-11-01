package crash

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultCrashConfig(t *testing.T) {
	cfg := DefaultCrashConfig()
	if !cfg.Enabled {
		t.Errorf("expected Enabled to be true")
	}
	if cfg.MaxReports != 200 {
		t.Errorf("expected MaxReports 200, got %d", cfg.MaxReports)
	}
	if cfg.DedupWindow != 15*time.Minute {
		t.Errorf("expected DedupWindow 15m, got %v", cfg.DedupWindow)
	}
	if err := ValidateCrashConfig(&cfg); err != nil {
		t.Errorf("expected DefaultCrashConfig to be valid: %v", err)
	}
}

func TestValidateCrashID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"crash_20261101_001", true},
		{"sigsegv-container-a1b2", true},
		{"core.1234", true},
		{"", false},
		{"   ", false},
		{strings.Repeat("a", 65), false},
		{"crash/path/traversal", false},
		{"crash;rm -rf", false},
		{"crash with spaces", false},
	}

	for _, tt := range tests {
		err := ValidateCrashID(tt.id)
		if tt.valid && err != nil {
			t.Errorf("ValidateCrashID(%q) unexpected error: %v", tt.id, err)
		} else if !tt.valid && err == nil {
			t.Errorf("ValidateCrashID(%q) expected error, got nil", tt.id)
		}
	}
}

func TestValidateCrashConfig(t *testing.T) {
	if err := ValidateCrashConfig(nil); err == nil {
		t.Errorf("expected error for nil config")
	}

	cfg := CrashConfig{
		MaxReports:       6000, // exceeds 5000
		DedupWindow:      10 * time.Minute,
		MaxCoreSizeBytes: 10 * 1024 * 1024,
	}
	if err := ValidateCrashConfig(&cfg); err == nil {
		t.Errorf("expected error for MaxReports > 5000")
	}

	cfg.MaxReports = 100
	cfg.DedupWindow = 48 * time.Hour // exceeds 24h
	if err := ValidateCrashConfig(&cfg); err == nil {
		t.Errorf("expected error for DedupWindow > 24h")
	}

	cfg.DedupWindow = 5 * time.Minute
	cfg.MaxCoreSizeBytes = 600 * 1024 * 1024 // exceeds 500MB
	if err := ValidateCrashConfig(&cfg); err == nil {
		t.Errorf("expected error for MaxCoreSizeBytes > 500MB")
	}

	// Test boundary adjustments
	cfg.MaxReports = -5
	cfg.DedupWindow = -1
	cfg.RetentionDuration = 0
	cfg.MaxCoreSizeBytes = 0
	cfg.WatchDirectory = ""
	if err := ValidateCrashConfig(&cfg); err != nil {
		t.Fatalf("unexpected error on boundary clamping: %v", err)
	}
	if cfg.MaxReports != 100 || cfg.DedupWindow != 5*time.Minute || cfg.WatchDirectory != "data/cores" {
		t.Errorf("boundaries not clamped correctly: %+v", cfg)
	}
}

func TestSignalName(t *testing.T) {
	cases := []struct {
		sig      int
		expected string
	}{
		{11, "SIGSEGV"},
		{6, "SIGABRT"},
		{9, "SIGKILL"},
		{137, "SIGKILL"}, // 128 + 9
		{139, "SIGSEGV"}, // 128 + 11
		{134, "SIGABRT"}, // 128 + 6
		{4, "SIGILL"},
		{7, "SIGBUS"},
		{8, "SIGFPE"},
		{99, "SIG#99"},
	}

	for _, c := range cases {
		got := SignalName(c.sig)
		if got != c.expected {
			t.Errorf("SignalName(%d) = %s; want %s", c.sig, got, c.expected)
		}
	}
}
