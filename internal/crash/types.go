package crash

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// RootCauseCategory represents the high-level classified cause of a process crash.
type RootCauseCategory string

const (
	RootCauseNullPointer        RootCauseCategory = "null_pointer_dereference"
	RootCauseMemoryCorruption   RootCauseCategory = "memory_corruption"
	RootCauseOutOfBounds        RootCauseCategory = "out_of_bounds_access"
	RootCauseAssertionFailure   RootCauseCategory = "assertion_failure"
	RootCauseOOMKilled          RootCauseCategory = "oom_killed"
	RootCauseStackOverflow      RootCauseCategory = "stack_overflow"
	RootCauseArithmeticError    RootCauseCategory = "arithmetic_exception"
	RootCauseIllegalInstruction RootCauseCategory = "illegal_instruction"
	RootCauseDeadlockTimeout    RootCauseCategory = "deadlock_timeout"
	RootCauseUnknown            RootCauseCategory = "unknown"
)

// CrashSeverity indicates the impact level of a container crash.
type CrashSeverity string

const (
	SeverityCritical CrashSeverity = "critical"
	SeverityHigh     CrashSeverity = "high"
	SeverityMedium   CrashSeverity = "medium"
	SeverityLow      CrashSeverity = "low"
)

// StackFrame represents a single function call frame in a stack backtrace.
type StackFrame struct {
	FrameIndex int    `json:"frame_index"`
	IP         uint64 `json:"ip"`
	Function   string `json:"function"`
	Module     string `json:"module"`
	SourceFile string `json:"source_file,omitempty"`
	Line       int    `json:"line,omitempty"`
	Offset     uint64 `json:"offset"`
}

// Backtrace captures the execution context and stack frames at the moment of failure.
type Backtrace struct {
	ThreadID     int               `json:"thread_id"`
	Signal       string            `json:"signal"`
	SignalNum    int               `json:"signal_num"`
	FaultAddress uint64            `json:"fault_address"`
	Registers    map[string]uint64 `json:"registers,omitempty"`
	Frames       []StackFrame      `json:"frames"`
}

// CrashReport encapsulates complete diagnostic telemetry for an intercepted crash.
type CrashReport struct {
	ID                string            `json:"id"`
	ContainerID       string            `json:"container_id"`
	ContainerName     string            `json:"container_name"`
	Image             string            `json:"image"`
	ExitCode          int               `json:"exit_code"`
	Signal            string            `json:"signal"`
	SignalNum         int               `json:"signal_num"`
	RootCause         RootCauseCategory `json:"root_cause"`
	Severity          CrashSeverity     `json:"severity"`
	Signature         string            `json:"signature"`
	Timestamp         time.Time         `json:"timestamp"`
	Hostname          string            `json:"hostname"`
	Backtrace         Backtrace         `json:"backtrace"`
	MemoryBytes       uint64            `json:"memory_bytes"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	DeduplicatedCount int               `json:"deduplicated_count"`
	FirstSeen         time.Time         `json:"first_seen"`
	LastSeen          time.Time         `json:"last_seen"`
}

// CrashConfig defines runtime parameters for the crash analysis pipeline.
type CrashConfig struct {
	Enabled           bool          `json:"enabled"`
	WatchDirectory    string        `json:"watch_directory"`
	MaxReports        int           `json:"max_reports"`
	RetentionDuration time.Duration `json:"retention_duration"`
	DedupWindow       time.Duration `json:"dedup_window"`
	AutoSymbolicate   bool          `json:"auto_symbolicate"`
	DispatchAlerts    bool          `json:"dispatch_alerts"`
	MaxCoreSizeBytes  int64         `json:"max_core_size_bytes"`
}

// CrashStatus exposes current telemetry and state of the crash analysis engine.
type CrashStatus struct {
	Enabled          bool           `json:"enabled"`
	TotalCrashes     int64          `json:"total_crashes"`
	UniqueSignatures int            `json:"unique_signatures"`
	ReportsStored    int            `json:"reports_stored"`
	DedupedCount     int64          `json:"deduped_count"`
	WatchDirectory   string         `json:"watch_directory"`
	LastCrashTime    time.Time      `json:"last_crash_time,omitempty"`
	RootCauseCounts  map[string]int `json:"root_cause_counts"`
}

var crashIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{1,64}$`)

// DefaultCrashConfig returns recommended production defaults.
func DefaultCrashConfig() CrashConfig {
	return CrashConfig{
		Enabled:           true,
		WatchDirectory:    "data/cores",
		MaxReports:        200,
		RetentionDuration: 72 * time.Hour,
		DedupWindow:       15 * time.Minute,
		AutoSymbolicate:   true,
		DispatchAlerts:    true,
		MaxCoreSizeBytes:  50 * 1024 * 1024, // 50MB safety cap
	}
}

// ValidateCrashID checks that a crash report identifier conforms to safe alphanumeric bounds.
func ValidateCrashID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("crash id cannot be empty")
	}
	if len(id) > 64 {
		return fmt.Errorf("crash id exceeds maximum length of 64 characters (got %d)", len(id))
	}
	if !crashIDRegex.MatchString(id) {
		return fmt.Errorf("crash id contains invalid characters: %s", id)
	}
	return nil
}

// ValidateCrashConfig checks boundaries on pipeline parameters.
func ValidateCrashConfig(cfg *CrashConfig) error {
	if cfg == nil {
		return errors.New("crash config cannot be nil")
	}
	if cfg.MaxReports <= 0 {
		cfg.MaxReports = 100
	}
	if cfg.MaxReports > 5000 {
		return fmt.Errorf("max reports cannot exceed 5000 (got %d)", cfg.MaxReports)
	}
	if cfg.DedupWindow <= 0 {
		cfg.DedupWindow = 5 * time.Minute
	}
	if cfg.DedupWindow > 24*time.Hour {
		return fmt.Errorf("dedup window cannot exceed 24 hours (got %v)", cfg.DedupWindow)
	}
	if cfg.RetentionDuration <= 0 {
		cfg.RetentionDuration = 24 * time.Hour
	}
	if cfg.MaxCoreSizeBytes <= 0 {
		cfg.MaxCoreSizeBytes = 10 * 1024 * 1024
	}
	if cfg.MaxCoreSizeBytes > 500*1024*1024 {
		return fmt.Errorf("max core size cannot exceed 500MB (got %d bytes)", cfg.MaxCoreSizeBytes)
	}
	cfg.WatchDirectory = strings.TrimSpace(cfg.WatchDirectory)
	if cfg.WatchDirectory == "" {
		cfg.WatchDirectory = "data/cores"
	}
	return nil
}

// SignalName returns standard posix signal names for integer values.
func SignalName(sig int) string {
	switch sig {
	case 1:
		return "SIGHUP"
	case 2:
		return "SIGINT"
	case 3:
		return "SIGQUIT"
	case 4:
		return "SIGILL"
	case 5:
		return "SIGTRAP"
	case 6:
		return "SIGABRT"
	case 7:
		return "SIGBUS"
	case 8:
		return "SIGFPE"
	case 9:
		return "SIGKILL"
	case 11:
		return "SIGSEGV"
	case 13:
		return "SIGPIPE"
	case 14:
		return "SIGALRM"
	case 15:
		return "SIGTERM"
	default:
		if sig > 128 && sig <= 165 {
			// Docker exit code convention: 128 + signal
			return SignalName(sig - 128)
		}
		return fmt.Sprintf("SIG#%d", sig)
	}
}
