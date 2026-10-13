package logs

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRingBuffer_BasicWrapAround(t *testing.T) {
	rb := NewRingBuffer(5)

	for i := 1; i <= 8; i++ {
		rb.Append(LogEntry{
			ID:        "c1",
			Stream:    "stdout",
			Timestamp: time.Now(),
			Message:   fmt.Sprintf("log-line-%d", i),
		})
	}

	if rb.Len() != 5 {
		t.Fatalf("expected capacity 5, got %d", rb.Len())
	}

	recent := rb.Recent(10, "")
	if len(recent) != 5 {
		t.Fatalf("expected 5 items returned, got %d", len(recent))
	}

	// Should contain lines 4, 5, 6, 7, 8 in chronological order
	if recent[0].Message != "log-line-4" {
		t.Errorf("expected first line to be log-line-4, got %s", recent[0].Message)
	}
	if recent[4].Message != "log-line-8" {
		t.Errorf("expected last line to be log-line-8, got %s", recent[4].Message)
	}
}

func TestRingBuffer_StreamFiltering(t *testing.T) {
	rb := NewRingBuffer(10)

	rb.Append(LogEntry{Stream: "stdout", Message: "out-1"})
	rb.Append(LogEntry{Stream: "stderr", Message: "err-1"})
	rb.Append(LogEntry{Stream: "stdout", Message: "out-2"})
	rb.Append(LogEntry{Stream: "system", Message: "sys-1"})
	rb.Append(LogEntry{Stream: "stderr", Message: "err-2"})

	stdouts := rb.Recent(10, "stdout")
	if len(stdouts) != 2 {
		t.Fatalf("expected 2 stdout entries, got %d", len(stdouts))
	}
	if stdouts[0].Message != "out-1" || stdouts[1].Message != "out-2" {
		t.Errorf("unexpected stdout entries: %+v", stdouts)
	}

	stderrs := rb.Recent(10, "stderr")
	if len(stderrs) != 2 {
		t.Fatalf("expected 2 stderr entries, got %d", len(stderrs))
	}
	if stderrs[0].Message != "err-1" || stderrs[1].Message != "err-2" {
		t.Errorf("unexpected stderr entries: %+v", stderrs)
	}

	systems := rb.Recent(10, "system")
	if len(systems) != 1 || systems[0].Message != "sys-1" {
		t.Errorf("unexpected system entries: %+v", systems)
	}
}

func TestRingBuffer_MessageTruncation(t *testing.T) {
	rb := NewRingBuffer(5)
	hugeMessage := strings.Repeat("A", 4000)

	rb.Append(LogEntry{Stream: "stdout", Message: hugeMessage})
	entries := rb.Recent(1, "")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry")
	}

	if len(entries[0].Message) > 2100 {
		t.Errorf("expected message to be truncated, got length %d", len(entries[0].Message))
	}
	if !strings.HasSuffix(entries[0].Message, "[truncated]") {
		t.Errorf("expected [truncated] suffix")
	}
}

func TestRingBuffer_MemoryBoundGuarantee(t *testing.T) {
	// 5000 max capacity filled with full lines
	rb := NewRingBuffer(5000)

	for i := 0; i < 6000; i++ {
		rb.Append(LogEntry{
			ID:        "container-long-uuid-12345678",
			Stream:    "stdout",
			Timestamp: time.Now(),
			Message:   "2026-10-14T05:00:00Z INFO HTTP GET /api/v1/metrics status=200 response_time=12ms",
		})
	}

	memBytes := rb.EstimateMemoryBytes()
	memMB := float64(memBytes) / (1024 * 1024)

	// Invariant: Must strictly stay under 15 MB
	if memMB >= 15.0 {
		t.Errorf("memory estimate %.2f MB exceeded 15 MB budget", memMB)
	}
	t.Logf("RingBuffer memory for 5000 entries: %.3f MB", memMB)
}

func TestRingBuffer_Concurrency(t *testing.T) {
	rb := NewRingBuffer(100)
	var wg sync.WaitGroup

	// 5 concurrent writers
	for w := 0; w < 5; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				rb.Append(LogEntry{
					ID:      fmt.Sprintf("w-%d", workerID),
					Stream:  "stdout",
					Message: fmt.Sprintf("msg-%d", i),
				})
			}
		}(w)
	}

	// 5 concurrent readers
	for r := 0; r < 5; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_ = rb.Recent(20, "")
				_ = rb.Len()
			}
		}()
	}

	wg.Wait()
	if rb.Len() != 100 {
		t.Errorf("expected length 100 after 500 total writes, got %d", rb.Len())
	}
}
