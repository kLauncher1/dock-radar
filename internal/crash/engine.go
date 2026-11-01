package crash

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
)

// ReportFilter specifies optional criteria for querying stored crash reports.
type ReportFilter struct {
	ContainerID string
	Severity    string
	RootCause   string
	Signature   string
	Limit       int
}

// Engine coordinates core dump interception, backtrace extraction, symbolication,
// root-cause classification, signature deduplication, and instant alert dispatch.
type Engine struct {
	mu              sync.RWMutex
	config          CrashConfig
	reports         []*CrashReport
	reportMap       map[string]*CrashReport
	rootCauseCounts map[string]int
	totalCrashes    atomic.Int64
	dedupedCount    atomic.Int64
	lastCrashTime   time.Time
	dedup           *DedupEngine
	symbolizer      *SymbolResolver
	alertDispatcher *alert.Dispatcher
	auditLogger     *audit.Logger
	dockerClient    *docker.Client
	stopCh          chan struct{}
	wg              sync.WaitGroup
}

// NewEngine initializes the master crash analysis engine with recommended defaults.
func NewEngine(cfg CrashConfig, alertDispatcher *alert.Dispatcher, auditLogger *audit.Logger, dockerClient *docker.Client) *Engine {
	if err := ValidateCrashConfig(&cfg); err != nil {
		cfg = DefaultCrashConfig()
	}
	return &Engine{
		config:          cfg,
		reports:         make([]*CrashReport, 0, cfg.MaxReports),
		reportMap:       make(map[string]*CrashReport),
		rootCauseCounts: make(map[string]int),
		dedup:           NewDedupEngine(cfg.DedupWindow, 1000),
		symbolizer:      NewSymbolResolver(),
		alertDispatcher: alertDispatcher,
		auditLogger:     auditLogger,
		dockerClient:    dockerClient,
		stopCh:          make(chan struct{}),
	}
}

// Start launches the background directory scanner and container crash watchdog.
func (e *Engine) Start(ctx context.Context) {
	e.wg.Add(1)
	go e.runBackgroundLoop(ctx)
}

// Stop cleanly terminates background tasks and releases resources.
func (e *Engine) Stop() {
	select {
	case <-e.stopCh:
		return
	default:
		close(e.stopCh)
	}
	e.wg.Wait()
}

// runBackgroundLoop runs periodic directory scans and maintenance sweeps.
func (e *Engine) runBackgroundLoop(ctx context.Context) {
	defer e.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case now := <-ticker.C:
			e.scanWatchDirectory(ctx)
			e.dedup.SweepExpired(now)
		}
	}
}

// scanWatchDirectory checks the configured watch directory for new core dump files.
func (e *Engine) scanWatchDirectory(ctx context.Context) {
	e.mu.RLock()
	dir := e.config.WatchDirectory
	enabled := e.config.Enabled
	e.mu.RUnlock()

	if !enabled || dir == "" {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return // Directory might not exist yet, ignore
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "core.") || strings.HasSuffix(name, ".dump") || strings.HasSuffix(name, ".core") {
			filePath := filepath.Join(dir, name)
			info, err := entry.Info()
			if err != nil || info.Size() > e.config.MaxCoreSizeBytes {
				continue
			}
			data, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}

			// Ingest core dump
			_, _ = e.IngestCrashDump(ctx, "container-host", name, "core-interceptor", data, map[string]string{
				"file_name": name,
				"source":    "watch_dir",
			})

			// Remove processed dump file to prevent repeated processing
			_ = os.Remove(filePath)
		}
	}
}

// IngestCrashDump processes a raw core dump or backtrace payload, classifies root cause,
// deduplicates signatures, stores report diagnostics, and dispatches webhook alerts.
func (e *Engine) IngestCrashDump(ctx context.Context, containerID, containerName, image string, rawDump []byte, metadata map[string]string) (*CrashReport, error) {
	e.mu.Lock()
	enabled := e.config.Enabled
	maxSize := e.config.MaxCoreSizeBytes
	autoSymbol := e.config.AutoSymbolicate
	dispatchAlert := e.config.DispatchAlerts
	maxReports := e.config.MaxReports
	e.mu.Unlock()

	if !enabled {
		return nil, errors.New("crash analysis pipeline is disabled")
	}
	if int64(len(rawDump)) > maxSize {
		return nil, fmt.Errorf("core dump payload exceeds maximum allowed size (%d > %d bytes)", len(rawDump), maxSize)
	}

	now := time.Now().UTC()
	bt, err := ParseCoreDumpOrTrace(rawDump)
	if err != nil {
		return nil, fmt.Errorf("failed to parse crash dump: %w", err)
	}

	if autoSymbol {
		e.symbolizer.SymbolicateBacktrace(&bt)
	}

	// Classify root cause and severity
	exitCode := 128 + bt.SignalNum
	cause, sev := ClassifyCrash(bt.SignalNum, bt.FaultAddress, bt.Frames, exitCode)

	repID := fmt.Sprintf("crash_%s_%s", now.Format("20060102_150405"), randomHex(4))
	if containerName == "" {
		containerName = containerID
	}

	report := &CrashReport{
		ID:            repID,
		ContainerID:   containerID,
		ContainerName: containerName,
		Image:         image,
		ExitCode:      exitCode,
		Signal:        bt.Signal,
		SignalNum:     bt.SignalNum,
		RootCause:     cause,
		Severity:      sev,
		Timestamp:     now,
		Hostname:      getHostName(),
		Backtrace:     bt,
		MemoryBytes:   uint64(len(rawDump)),
		Metadata:      metadata,
	}

	// Deduplication evaluation
	isDup, dedupCount, shouldAlert := e.dedup.Process(report, now)
	e.totalCrashes.Add(1)

	e.mu.Lock()
	e.lastCrashTime = now
	e.rootCauseCounts[string(cause)]++

	if isDup {
		e.dedupedCount.Add(1)
		// Update existing report if found
		if existing, ok := e.reportMap[report.Signature]; ok {
			existing.DeduplicatedCount = dedupCount
			existing.LastSeen = now
			report = existing
		}
	} else {
		// Bounded circular storage
		if len(e.reports) >= maxReports {
			evicted := e.reports[0]
			e.reports = e.reports[1:]
			delete(e.reportMap, evicted.Signature)
			delete(e.reportMap, evicted.ID)
		}
		e.reports = append(e.reports, report)
		e.reportMap[report.ID] = report
		e.reportMap[report.Signature] = report
	}
	e.mu.Unlock()

	// Audit logging
	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action:   "container_crash_intercepted",
			Actor:    "crash-pipeline",
			Target:   containerID,
			ClientIP: "127.0.0.1",
			Status:   "alerted",
			Details: map[string]any{
				"crash_id":         report.ID,
				"signal":           report.Signal,
				"root_cause":       string(report.RootCause),
				"severity":         string(report.Severity),
				"signature":        report.Signature,
				"is_duplicate":     isDup,
				"dedup_count":      dedupCount,
				"frames_extracted": len(report.Backtrace.Frames),
			},
		})
	}

	// Webhook notification dispatch
	if dispatchAlert && shouldAlert && e.alertDispatcher != nil {
		alertLevel := alert.LevelCritical
		if report.Severity == SeverityMedium || report.Severity == SeverityLow {
			alertLevel = alert.LevelWarning
		}

		topFrame := "unknown"
		if len(report.Backtrace.Frames) > 0 {
			f := report.Backtrace.Frames[0]
			topFrame = fmt.Sprintf("%s (%s:%d)", f.Function, f.SourceFile, f.Line)
		}

		_ = e.alertDispatcher.Dispatch(ctx, alert.Event{
			Level:     alertLevel,
			Source:    "dock-radar.crash",
			EventType: "container_crash",
			Message: fmt.Sprintf("Container %s crashed with %s (%s). Top frame: %s. Dedup signature: %s (occurrences: %d)",
				report.ContainerName, report.Signal, report.RootCause, topFrame, report.Signature, dedupCount),
			Details: map[string]any{
				"crash_id":       report.ID,
				"container_id":   report.ContainerID,
				"container_name": report.ContainerName,
				"image":          report.Image,
				"signal":         report.Signal,
				"root_cause":     string(report.RootCause),
				"severity":       string(report.Severity),
				"signature":      report.Signature,
				"dedup_count":    dedupCount,
				"fault_address":  fmt.Sprintf("0x%x", report.Backtrace.FaultAddress),
			},
		})
	}

	return report, nil
}

// TriggerTestCrash generates a synthetic test crash report for operational triage and alert drills.
func (e *Engine) TriggerTestCrash(containerID string) (*CrashReport, error) {
	if containerID == "" {
		containerID = "drill-container-01"
	}
	syntheticTrace := fmt.Sprintf(`Program received signal SIGSEGV, Segmentation fault.
0x0000000000401142 in execute_query (query=0x0) at db_pool.c:89
#0  0x0000000000401142 in execute_query (query=0x0) at db_pool.c:89
#1  0x0000000000401280 in handle_client_request (req=0x7ffe) at server.c:142
#2  0x0000000000401560 in worker_loop (arg=0x0) at worker.c:35
#3  0x00007ffff7bc4609 in start_thread (arg=0x7ffff7db7640) at pthread_create.c:477
#4  0x00007ffff7ae7293 in clone () at clone.S:95`)

	return e.IngestCrashDump(context.Background(), containerID, "test-"+containerID, "drill/crash-test:latest", []byte(syntheticTrace), map[string]string{
		"simulation": "manual_drill",
	})
}

// Reports returns a filtered list of stored crash reports (newest first).
func (e *Engine) Reports(filter ReportFilter) []*CrashReport {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*CrashReport, 0, len(e.reports))
	for i := len(e.reports) - 1; i >= 0; i-- {
		rep := e.reports[i]
		if filter.ContainerID != "" && rep.ContainerID != filter.ContainerID {
			continue
		}
		if filter.Severity != "" && string(rep.Severity) != filter.Severity {
			continue
		}
		if filter.RootCause != "" && string(rep.RootCause) != filter.RootCause {
			continue
		}
		if filter.Signature != "" && rep.Signature != filter.Signature {
			continue
		}
		result = append(result, rep)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result
}

// Report retrieves a single crash report by ID or signature.
func (e *Engine) Report(id string) (*CrashReport, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rep, ok := e.reportMap[id]
	return rep, ok
}

// ClearReports empties the stored in-memory crash reports buffer.
func (e *Engine) ClearReports() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reports = make([]*CrashReport, 0, e.config.MaxReports)
	e.reportMap = make(map[string]*CrashReport)
}

// Status returns a telemetry snapshot of the crash pipeline.
func (e *Engine) Status() CrashStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	countsCopy := make(map[string]int, len(e.rootCauseCounts))
	for k, v := range e.rootCauseCounts {
		countsCopy[k] = v
	}

	return CrashStatus{
		Enabled:          e.config.Enabled,
		TotalCrashes:     e.totalCrashes.Load(),
		UniqueSignatures: e.dedup.UniqueCount(),
		ReportsStored:    len(e.reports),
		DedupedCount:     e.dedupedCount.Load(),
		WatchDirectory:   e.config.WatchDirectory,
		LastCrashTime:    e.lastCrashTime,
		RootCauseCounts:  countsCopy,
	}
}

// Config returns a copy of the current engine configuration.
func (e *Engine) Config() CrashConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

// UpdateConfig updates the engine parameters after validating boundaries.
func (e *Engine) UpdateConfig(cfg CrashConfig) error {
	if err := ValidateCrashConfig(&cfg); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = cfg
	return nil
}

// DedupEntries returns active deduplication signature records.
func (e *Engine) DedupEntries() []*DedupEntry {
	return e.dedup.Entries()
}

func randomHex(bytesLen int) string {
	b := make([]byte, bytesLen)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "abcd"
	}
	return hex.EncodeToString(b)
}

func getHostName() string {
	h, err := os.Hostname()
	if err != nil {
		return "dock-radar-node"
	}
	return h
}
