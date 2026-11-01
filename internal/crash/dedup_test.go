package crash

import (
	"sync"
	"testing"
	"time"
)

func TestComputeCrashSignature_Deterministic(t *testing.T) {
	rep1 := &CrashReport{
		Signal:    "SIGSEGV",
		RootCause: RootCauseNullPointer,
		Image:     "postgres:15-alpine",
		Backtrace: Backtrace{
			Frames: []StackFrame{
				{Function: "AllocSetAlloc", Module: "postgres"},
				{Function: "MemoryContextAlloc", Module: "postgres"},
			},
		},
	}
	rep2 := &CrashReport{
		Signal:    "SIGSEGV",
		RootCause: RootCauseNullPointer,
		Image:     "postgres:15-alpine",
		Backtrace: Backtrace{
			Frames: []StackFrame{
				{Function: "AllocSetAlloc", Module: "postgres"},
				{Function: "MemoryContextAlloc", Module: "postgres"},
			},
		},
	}
	repDifferent := &CrashReport{
		Signal:    "SIGABRT",
		RootCause: RootCauseAssertionFailure,
		Image:     "postgres:15-alpine",
		Backtrace: Backtrace{
			Frames: []StackFrame{
				{Function: "abort", Module: "libc"},
			},
		},
	}

	sig1 := ComputeCrashSignature(rep1)
	sig2 := ComputeCrashSignature(rep2)
	sigDiff := ComputeCrashSignature(repDifferent)

	if sig1 != sig2 {
		t.Errorf("expected deterministic signatures, got %s != %s", sig1, sig2)
	}
	if sig1 == sigDiff {
		t.Errorf("expected different signatures for different crashes, got %s", sig1)
	}
	if len(sig1) != 26 || sig1[:10] != "crash_sig_" {
		t.Errorf("unexpected signature format: %s", sig1)
	}
}

func TestDedupEngine_ProcessAndThrottling(t *testing.T) {
	engine := NewDedupEngine(10*time.Minute, 100)
	now := time.Now().UTC()

	report := &CrashReport{
		ID:        "crash-001",
		Signal:    "SIGSEGV",
		RootCause: RootCauseNullPointer,
		Image:     "nginx:alpine",
		Backtrace: Backtrace{
			Frames: []StackFrame{
				{Function: "ngx_http_process_request", Module: "nginx"},
			},
		},
	}

	// 1st occurrence: should alert
	isDup, count, shouldAlert := engine.Process(report, now)
	if isDup {
		t.Errorf("expected isDup=false on first occurrence")
	}
	if count != 1 {
		t.Errorf("expected count=1, got %d", count)
	}
	if !shouldAlert {
		t.Errorf("expected shouldAlert=true on first occurrence")
	}

	// 2nd occurrence: duplicate, throttled (no alert)
	isDup, count, shouldAlert = engine.Process(report, now.Add(1*time.Minute))
	if !isDup {
		t.Errorf("expected isDup=true on 2nd occurrence")
	}
	if count != 2 {
		t.Errorf("expected count=2, got %d", count)
	}
	if shouldAlert {
		t.Errorf("expected shouldAlert=false on 2nd occurrence (throttled)")
	}

	// 5th occurrence: triggers milestone alert
	for i := 3; i <= 5; i++ {
		isDup, count, shouldAlert = engine.Process(report, now.Add(time.Duration(i)*time.Minute))
	}
	if count != 5 || !shouldAlert {
		t.Errorf("expected count=5 and shouldAlert=true on 5th milestone, got count=%d alert=%v", count, shouldAlert)
	}
}

func TestDedupEngine_SweepAndEviction(t *testing.T) {
	engine := NewDedupEngine(5*time.Minute, 2) // capacity 2
	baseTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)

	rep1 := &CrashReport{ID: "c1", Signal: "SIGSEGV", RootCause: RootCauseNullPointer}
	rep2 := &CrashReport{ID: "c2", Signal: "SIGABRT", RootCause: RootCauseAssertionFailure}
	rep3 := &CrashReport{ID: "c3", Signal: "SIGILL", RootCause: RootCauseIllegalInstruction}

	engine.Process(rep1, baseTime)
	engine.Process(rep2, baseTime.Add(1*time.Minute))
	if engine.UniqueCount() != 2 {
		t.Fatalf("expected 2 unique signatures, got %d", engine.UniqueCount())
	}

	// Ingesting rep3 should evict rep1 (oldest)
	engine.Process(rep3, baseTime.Add(2*time.Minute))
	if engine.UniqueCount() != 2 {
		t.Errorf("expected capacity 2 maintained after eviction, got %d", engine.UniqueCount())
	}

	// Sweep with cutoff after rep2's expiration
	evicted := engine.SweepExpired(baseTime.Add(10 * time.Minute))
	if evicted != 2 {
		t.Errorf("expected 2 evicted in sweep, got %d", evicted)
	}
	if engine.UniqueCount() != 0 {
		t.Errorf("expected 0 entries after full sweep, got %d", engine.UniqueCount())
	}
}

func TestDedupEngine_Concurrency(t *testing.T) {
	engine := NewDedupEngine(15*time.Minute, 500)
	var wg sync.WaitGroup
	now := time.Now().UTC()

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			rep := &CrashReport{
				ID:        "crash-concurrent",
				Signal:    "SIGSEGV",
				RootCause: RootCauseNullPointer,
				Image:     "app:latest",
			}
			engine.Process(rep, now)
		}(i)
	}

	wg.Wait()
	if engine.UniqueCount() != 1 {
		t.Errorf("expected 1 shared unique signature, got %d", engine.UniqueCount())
	}
}
