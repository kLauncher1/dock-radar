package raft

import (
	"sync"
	"testing"
	"time"
)

func TestRaftLog_AppendAndGet(t *testing.T) {
	log := NewRaftLog()

	lastIdx, lastTerm := log.LastIndexTerm()
	if lastIdx != 0 || lastTerm != 0 {
		t.Fatalf("expected initial index 0 term 0, got %d %d", lastIdx, lastTerm)
	}

	idx1 := log.Append(LogEntry{Term: 1, Type: CmdClusterConfig, Data: []byte("a")})
	if idx1 != 1 {
		t.Fatalf("expected idx 1, got %d", idx1)
	}

	idx2 := log.Append(LogEntry{Term: 1, Type: CmdClusterConfig, Data: []byte("b")})
	if idx2 != 2 {
		t.Fatalf("expected idx 2, got %d", idx2)
	}

	lastIdx, lastTerm = log.LastIndexTerm()
	if lastIdx != 2 || lastTerm != 1 {
		t.Fatalf("expected lastIdx 2 lastTerm 1, got %d %d", lastIdx, lastTerm)
	}

	entry1, ok := log.Get(1)
	if !ok || string(entry1.Data) != "a" {
		t.Errorf("failed to get entry 1: %+v", entry1)
	}

	entry2, ok := log.Get(2)
	if !ok || string(entry2.Data) != "b" {
		t.Errorf("failed to get entry 2: %+v", entry2)
	}

	_, ok = log.Get(3)
	if ok {
		t.Errorf("expected false for out of bound index 3")
	}
}

func TestRaftLog_TruncateSuffix(t *testing.T) {
	log := NewRaftLog()
	log.Append(LogEntry{Term: 1, Data: []byte("1")})
	log.Append(LogEntry{Term: 1, Data: []byte("2")})
	log.Append(LogEntry{Term: 2, Data: []byte("3")})
	log.Append(LogEntry{Term: 2, Data: []byte("4")})

	if log.Len() != 4 {
		t.Fatalf("expected length 4, got %d", log.Len())
	}

	// Truncate starting at index 3
	log.TruncateSuffix(3)
	if log.Len() != 2 {
		t.Fatalf("expected length 2 after truncate, got %d", log.Len())
	}

	lastIdx, lastTerm := log.LastIndexTerm()
	if lastIdx != 2 || lastTerm != 1 {
		t.Fatalf("expected lastIdx 2 lastTerm 1, got %d %d", lastIdx, lastTerm)
	}

	_, ok := log.Get(3)
	if ok {
		t.Errorf("expected index 3 to be truncated")
	}
}

func TestRaftLog_Compact(t *testing.T) {
	log := NewRaftLog()
	for i := 1; i <= 10; i++ {
		log.Append(LogEntry{Term: 1, Data: []byte{byte(i)}})
	}

	// Compact up to index 5
	log.Compact(5, 1)

	if log.Len() != 5 {
		t.Fatalf("expected 5 entries remaining in memory, got %d", log.Len())
	}

	lastIdx, lastTerm := log.LastIndexTerm()
	if lastIdx != 10 || lastTerm != 1 {
		t.Fatalf("expected lastIdx 10 lastTerm 1, got %d %d", lastIdx, lastTerm)
	}

	// Index 5 (snapshot boundary) should return snapshot metadata
	entry5, ok := log.Get(5)
	if !ok || entry5.Index != 5 || entry5.Term != 1 {
		t.Errorf("expected entry at snapshot index 5: %+v", entry5)
	}

	// Index 4 is compacted away
	_, ok = log.Get(4)
	if ok {
		t.Errorf("expected index 4 to be purged")
	}

	// Index 6 should still exist in memory
	entry6, ok := log.Get(6)
	if !ok || entry6.Index != 6 {
		t.Errorf("expected index 6 to exist: %+v", entry6)
	}
}

func TestRaftLog_Slice(t *testing.T) {
	log := NewRaftLog()
	for i := 1; i <= 5; i++ {
		log.Append(LogEntry{Term: 1, Data: []byte{byte(i)}})
	}

	slice := log.Slice(3)
	if len(slice) != 3 {
		t.Fatalf("expected 3 entries in slice, got %d", len(slice))
	}
	if slice[0].Index != 3 || slice[2].Index != 5 {
		t.Errorf("slice indices mismatch: %+v", slice)
	}
}

func TestRaftLog_Concurrency(t *testing.T) {
	log := NewRaftLog()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(val int) {
			defer wg.Done()
			log.Append(LogEntry{Term: 1, Timestamp: time.Now()})
			_, _ = log.LastIndexTerm()
			_ = log.Len()
		}(i)
	}

	wg.Wait()
	if log.Len() != 50 {
		t.Errorf("expected 50 entries, got %d", log.Len())
	}
}
