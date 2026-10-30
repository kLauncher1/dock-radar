package raft

import (
	"sync"
	"time"
)

// RaftLog manages an indexed sequence of replicated log entries and snapshot checkpoints.
type RaftLog struct {
	mu            sync.RWMutex
	entries       []LogEntry
	snapshotIndex uint64
	snapshotTerm  uint64
	lastCompacted time.Time
}

// NewRaftLog initializes a log with an empty baseline (index 0, term 0).
func NewRaftLog() *RaftLog {
	return &RaftLog{
		entries:       make([]LogEntry, 0, 1024),
		snapshotIndex: 0,
		snapshotTerm:  0,
		lastCompacted: time.Now().UTC(),
	}
}

// LastIndexTerm returns the index and term of the most recent log entry.
func (l *RaftLog) LastIndexTerm() (uint64, uint64) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(l.entries) == 0 {
		return l.snapshotIndex, l.snapshotTerm
	}
	last := l.entries[len(l.entries)-1]
	return last.Index, last.Term
}

// Get returns the log entry at the specified 1-based absolute index.
func (l *RaftLog) Get(index uint64) (LogEntry, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if index <= l.snapshotIndex {
		if index == l.snapshotIndex {
			return LogEntry{
				Index: l.snapshotIndex,
				Term:  l.snapshotTerm,
			}, true
		}
		return LogEntry{}, false
	}

	offset := index - l.snapshotIndex - 1
	if offset >= uint64(len(l.entries)) {
		return LogEntry{}, false
	}
	return l.entries[offset], true
}

// Append inserts a single log entry into the log, ensuring monotonic indexing.
func (l *RaftLog) Append(entry LogEntry) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	var expectedIndex uint64
	if len(l.entries) == 0 {
		expectedIndex = l.snapshotIndex + 1
	} else {
		expectedIndex = l.entries[len(l.entries)-1].Index + 1
	}

	if entry.Index == 0 {
		entry.Index = expectedIndex
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	l.entries = append(l.entries, entry)
	return entry.Index
}

// AppendEntries inserts multiple log entries sequentially into the log.
func (l *RaftLog) AppendEntries(entries []LogEntry) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, entry := range entries {
		var expectedIndex uint64
		if len(l.entries) == 0 {
			expectedIndex = l.snapshotIndex + 1
		} else {
			expectedIndex = l.entries[len(l.entries)-1].Index + 1
		}
		if entry.Index == 0 {
			entry.Index = expectedIndex
		}
		if entry.Timestamp.IsZero() {
			entry.Timestamp = time.Now().UTC()
		}
		l.entries = append(l.entries, entry)
	}

	if len(l.entries) == 0 {
		return l.snapshotIndex
	}
	return l.entries[len(l.entries)-1].Index
}

// Slice returns all entries from fromIndex (inclusive) up to the end of the log.
func (l *RaftLog) Slice(fromIndex uint64) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if fromIndex <= l.snapshotIndex {
		fromIndex = l.snapshotIndex + 1
	}
	offset := fromIndex - l.snapshotIndex - 1
	if offset >= uint64(len(l.entries)) {
		return nil
	}

	result := make([]LogEntry, len(l.entries)-int(offset))
	copy(result, l.entries[offset:])
	return result
}

// TruncateSuffix removes all entries starting at fromIndex (inclusive).
func (l *RaftLog) TruncateSuffix(fromIndex uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if fromIndex <= l.snapshotIndex {
		l.entries = l.entries[:0]
		return
	}

	offset := fromIndex - l.snapshotIndex - 1
	if offset < uint64(len(l.entries)) {
		l.entries = l.entries[:offset]
	}
}

// Compact discards entries up to snapshotIndex and records the snapshot boundary.
func (l *RaftLog) Compact(snapshotIndex uint64, snapshotTerm uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if snapshotIndex <= l.snapshotIndex {
		return
	}

	offset := snapshotIndex - l.snapshotIndex
	if offset >= uint64(len(l.entries)) {
		l.entries = l.entries[:0]
	} else {
		l.entries = l.entries[offset:]
	}

	l.snapshotIndex = snapshotIndex
	l.snapshotTerm = snapshotTerm
	l.lastCompacted = time.Now().UTC()
}

// Len returns the count of currently held entries in memory.
func (l *RaftLog) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}
