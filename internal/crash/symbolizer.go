package crash

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// SymbolEntry maps a contiguous virtual address range to a resolved function and module.
type SymbolEntry struct {
	StartAddr  uint64 `json:"start_addr"`
	EndAddr    uint64 `json:"end_addr"`
	Function   string `json:"function"`
	Module     string `json:"module"`
	SourceFile string `json:"source_file,omitempty"`
	Line       int    `json:"line,omitempty"`
}

// SymbolResolver performs in-memory symbolication and root-cause classification on raw backtraces.
type SymbolResolver struct {
	mu      sync.RWMutex
	symbols []SymbolEntry
}

// NewSymbolResolver initializes a thread-safe symbol resolver.
func NewSymbolResolver() *SymbolResolver {
	return &SymbolResolver{
		symbols: make([]SymbolEntry, 0),
	}
}

// RegisterSymbol inserts a symbol mapping, keeping the internal slice sorted by start address.
func (r *SymbolResolver) RegisterSymbol(sym SymbolEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.symbols = append(r.symbols, sym)
	sort.Slice(r.symbols, func(i, j int) bool {
		return r.symbols[i].StartAddr < r.symbols[j].StartAddr
	})
}

// Resolve looks up a virtual instruction pointer, returning symbol details and offset from function base.
func (r *SymbolResolver) Resolve(addr uint64) (function, module, file string, line int, offset uint64, found bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Binary search for entry containing addr
	idx := sort.Search(len(r.symbols), func(i int) bool {
		return r.symbols[i].EndAddr > addr
	})

	if idx < len(r.symbols) && addr >= r.symbols[idx].StartAddr && addr < r.symbols[idx].EndAddr {
		sym := r.symbols[idx]
		return sym.Function, sym.Module, sym.SourceFile, sym.Line, addr - sym.StartAddr, true
	}

	return "", "", "", 0, 0, false
}

// SymbolicateBacktrace enriches raw stack frames with resolved symbol names and source locations.
func (r *SymbolResolver) SymbolicateBacktrace(bt *Backtrace) {
	if bt == nil {
		return
	}
	for i := range bt.Frames {
		frame := &bt.Frames[i]
		if fn, mod, file, line, off, ok := r.Resolve(frame.IP); ok {
			frame.Function = fn
			if mod != "" {
				frame.Module = mod
			}
			if file != "" {
				frame.SourceFile = file
			}
			if line != 0 {
				frame.Line = line
			}
			frame.Offset = off
		} else if frame.Function == "" {
			frame.Function = fmt.Sprintf("sub_%x", frame.IP)
		}
	}
}

// ClassifyCrash triages crash telemetry, categorizing the root cause and severity level.
func ClassifyCrash(signalNum int, faultAddr uint64, frames []StackFrame, exitCode int) (RootCauseCategory, CrashSeverity) {
	// 1. OOM detection: exit 137 or SIGKILL (9)
	if exitCode == 137 || signalNum == 9 {
		return RootCauseOOMKilled, SeverityHigh
	}

	// 2. SIGFPE: arithmetic faults
	if signalNum == 8 {
		return RootCauseArithmeticError, SeverityMedium
	}

	// 3. SIGILL: illegal instruction
	if signalNum == 4 {
		return RootCauseIllegalInstruction, SeverityHigh
	}

	// 4. SIGABRT: assertion failures and aborts
	if signalNum == 6 || exitCode == 134 {
		for _, f := range frames {
			fn := strings.ToLower(f.Function)
			if strings.Contains(fn, "assert") || strings.Contains(fn, "panic") {
				return RootCauseAssertionFailure, SeverityHigh
			}
		}
		return RootCauseAssertionFailure, SeverityHigh
	}

	// 5. Stack overflow: recursive call chain detection
	if len(frames) >= 8 {
		repeats := 0
		for i := 1; i < len(frames); i++ {
			if frames[i].Function != "" && frames[i].Function == frames[i-1].Function {
				repeats++
			}
		}
		if repeats >= 4 {
			return RootCauseStackOverflow, SeverityCritical
		}
	}

	// 6. SIGSEGV / SIGBUS inspection
	if signalNum == 11 || signalNum == 7 || exitCode == 139 {
		// Null pointer dereference: fault address falls within Linux zero page (< 4096 bytes / 0x1000)
		if faultAddr < 0x1000 {
			return RootCauseNullPointer, SeverityCritical
		}

		// Check for heap corruption / out of bounds signatures in frame names
		for _, f := range frames {
			fn := strings.ToLower(f.Function)
			if strings.Contains(fn, "bounds") || strings.Contains(fn, "indexoutofrange") || strings.Contains(fn, "slice") {
				return RootCauseOutOfBounds, SeverityCritical
			}
			if strings.Contains(fn, "malloc") || strings.Contains(fn, "free") || strings.Contains(fn, "corrupt") {
				return RootCauseMemoryCorruption, SeverityCritical
			}
		}

		return RootCauseMemoryCorruption, SeverityCritical
	}

	// 7. Deadlock or watchdog timeout
	if exitCode == 124 {
		return RootCauseDeadlockTimeout, SeverityMedium
	}

	return RootCauseUnknown, SeverityLow
}
