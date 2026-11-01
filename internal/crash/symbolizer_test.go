package crash

import (
	"testing"
)

func TestSymbolResolver_ResolveAndEnrich(t *testing.T) {
	resolver := NewSymbolResolver()

	resolver.RegisterSymbol(SymbolEntry{
		StartAddr:  0x00401000,
		EndAddr:    0x00401100,
		Function:   "handle_connection",
		Module:     "dock-radar",
		SourceFile: "server.c",
		Line:       102,
	})
	resolver.RegisterSymbol(SymbolEntry{
		StartAddr:  0x00401100,
		EndAddr:    0x00401250,
		Function:   "parse_headers",
		Module:     "dock-radar",
		SourceFile: "http.c",
		Line:       45,
	})

	fn, mod, file, line, off, found := resolver.Resolve(0x00401050)
	if !found {
		t.Fatalf("expected symbol at 0x00401050 to be found")
	}
	if fn != "handle_connection" || mod != "dock-radar" || file != "server.c" || line != 102 || off != 0x50 {
		t.Errorf("unexpected symbol resolution: fn=%s mod=%s file=%s line=%d off=0x%x", fn, mod, file, line, off)
	}

	// Address out of bounds
	_, _, _, _, _, found = resolver.Resolve(0x00500000)
	if found {
		t.Errorf("expected 0x00500000 to not be found")
	}

	// Test backtrace enrichment
	bt := Backtrace{
		Frames: []StackFrame{
			{IP: 0x00401120},
			{IP: 0x00900000},
		},
	}
	resolver.SymbolicateBacktrace(&bt)
	if bt.Frames[0].Function != "parse_headers" || bt.Frames[0].Line != 45 {
		t.Errorf("frame 0 enrichment failed: %+v", bt.Frames[0])
	}
	if bt.Frames[1].Function != "sub_900000" {
		t.Errorf("frame 1 fallback name failed: %s", bt.Frames[1].Function)
	}
}

func TestClassifyCrash(t *testing.T) {
	tests := []struct {
		name       string
		sig        int
		faultAddr  uint64
		frames     []StackFrame
		exitCode   int
		wantCause  RootCauseCategory
		wantSevere CrashSeverity
	}{
		{
			name:       "Null pointer dereference",
			sig:        11,
			faultAddr:  0x0,
			frames:     []StackFrame{{Function: "deref_ptr"}},
			exitCode:   139,
			wantCause:  RootCauseNullPointer,
			wantSevere: SeverityCritical,
		},
		{
			name:       "OOM killed exit code 137",
			sig:        9,
			faultAddr:  0,
			frames:     nil,
			exitCode:   137,
			wantCause:  RootCauseOOMKilled,
			wantSevere: SeverityHigh,
		},
		{
			name:       "Assertion failure SIGABRT",
			sig:        6,
			faultAddr:  0,
			frames:     []StackFrame{{Function: "__assert_fail"}},
			exitCode:   134,
			wantCause:  RootCauseAssertionFailure,
			wantSevere: SeverityHigh,
		},
		{
			name:       "Arithmetic exception SIGFPE",
			sig:        8,
			faultAddr:  0,
			frames:     []StackFrame{{Function: "divide"}},
			exitCode:   136,
			wantCause:  RootCauseArithmeticError,
			wantSevere: SeverityMedium,
		},
		{
			name:       "Illegal instruction SIGILL",
			sig:        4,
			faultAddr:  0,
			frames:     []StackFrame{{Function: "invalid_opcode"}},
			exitCode:   132,
			wantCause:  RootCauseIllegalInstruction,
			wantSevere: SeverityHigh,
		},
		{
			name:      "Stack overflow recursive",
			sig:       11,
			faultAddr: 0x7ffe0000,
			frames: []StackFrame{
				{Function: "recurse"},
				{Function: "recurse"},
				{Function: "recurse"},
				{Function: "recurse"},
				{Function: "recurse"},
				{Function: "recurse"},
				{Function: "recurse"},
				{Function: "recurse"},
			},
			exitCode:   139,
			wantCause:  RootCauseStackOverflow,
			wantSevere: SeverityCritical,
		},
		{
			name:       "Out of bounds access",
			sig:        11,
			faultAddr:  0x1000000,
			frames:     []StackFrame{{Function: "check_slice_bounds"}},
			exitCode:   139,
			wantCause:  RootCauseOutOfBounds,
			wantSevere: SeverityCritical,
		},
		{
			name:       "Heap memory corruption",
			sig:        11,
			faultAddr:  0xdeadbeef,
			frames:     []StackFrame{{Function: "free_corrupted"}},
			exitCode:   139,
			wantCause:  RootCauseMemoryCorruption,
			wantSevere: SeverityCritical,
		},
		{
			name:       "Deadlock timeout",
			sig:        15,
			faultAddr:  0,
			frames:     nil,
			exitCode:   124,
			wantCause:  RootCauseDeadlockTimeout,
			wantSevere: SeverityMedium,
		},
		{
			name:       "Unknown fallback",
			sig:        2,
			faultAddr:  0,
			frames:     nil,
			exitCode:   1,
			wantCause:  RootCauseUnknown,
			wantSevere: SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cause, sev := ClassifyCrash(tt.sig, tt.faultAddr, tt.frames, tt.exitCode)
			if cause != tt.wantCause {
				t.Errorf("cause = %v; want %v", cause, tt.wantCause)
			}
			if sev != tt.wantSevere {
				t.Errorf("severity = %v; want %v", sev, tt.wantSevere)
			}
		})
	}
}
