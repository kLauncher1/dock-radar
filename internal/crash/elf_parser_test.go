package crash

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseTextBacktrace_GDB(t *testing.T) {
	text := `
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401142 in crash_handler (fault_address=0x0) at server.c:89
#0  0x0000000000401142 in crash_handler (fault_address=0x0) at server.c:89
#1  0x0000000000401280 in process_request (req=0x7ffe) at http.c:142
#2  0x0000000000401560 in main (argc=1, argv=0x7fff) at main.c:35
`
	bt, err := ParseCoreDumpOrTrace([]byte(text))
	if err != nil {
		t.Fatalf("ParseCoreDumpOrTrace failed: %v", err)
	}

	if bt.Signal != "SIGSEGV" || bt.SignalNum != 11 {
		t.Errorf("expected SIGSEGV (11), got %s (%d)", bt.Signal, bt.SignalNum)
	}

	if len(bt.Frames) != 3 {
		t.Fatalf("expected 3 stack frames, got %d", len(bt.Frames))
	}

	if bt.Frames[0].Function != "crash_handler" || bt.Frames[0].SourceFile != "server.c" || bt.Frames[0].Line != 89 {
		t.Errorf("frame 0 mismatch: %+v", bt.Frames[0])
	}
	if bt.Frames[1].Function != "process_request" || bt.Frames[1].SourceFile != "http.c" || bt.Frames[1].Line != 142 {
		t.Errorf("frame 1 mismatch: %+v", bt.Frames[1])
	}
	if bt.Frames[2].Function != "main" || bt.Frames[2].SourceFile != "main.c" || bt.Frames[2].Line != 35 {
		t.Errorf("frame 2 mismatch: %+v", bt.Frames[2])
	}
}

func TestParseTextBacktrace_GoPanic(t *testing.T) {
	text := `
fatal error: panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation fault code=0x1 addr=0x0 pc=0x4a1234]

goroutine 1 [running]:
github.com/example/app/pkg/worker.ProcessMessage(0xc00008)
	/go/src/app/pkg/worker/worker.go:56 +0x24
github.com/example/app/cmd.Run()
	/go/src/app/cmd/main.go:24 +0x8a
`
	bt, err := ParseCoreDumpOrTrace([]byte(text))
	if err != nil {
		t.Fatalf("ParseCoreDumpOrTrace failed: %v", err)
	}

	if bt.Signal != "SIGSEGV" {
		t.Errorf("expected SIGSEGV, got %s", bt.Signal)
	}

	if len(bt.Frames) != 2 {
		t.Fatalf("expected 2 stack frames, got %d", len(bt.Frames))
	}

	if bt.Frames[0].Function != "github.com/example/app/pkg/worker.ProcessMessage" || bt.Frames[0].Line != 56 {
		t.Errorf("frame 0 mismatch: %+v", bt.Frames[0])
	}
	if bt.Frames[1].Function != "github.com/example/app/cmd.Run" || bt.Frames[1].Line != 24 {
		t.Errorf("frame 1 mismatch: %+v", bt.Frames[1])
	}
}

func TestParseCoreDump_SyntheticELF(t *testing.T) {
	elfBytes := buildSyntheticELFCore(11, 4242, 0x00401142, 0x7ffeef00, 0x0)
	bt, err := ParseCoreDumpOrTrace(elfBytes)
	if err != nil {
		t.Fatalf("ParseCoreDumpOrTrace on synthetic ELF core failed: %v", err)
	}

	if bt.SignalNum != 11 || bt.Signal != "SIGSEGV" {
		t.Errorf("expected signal 11 / SIGSEGV, got %d / %s", bt.SignalNum, bt.Signal)
	}
	if bt.ThreadID != 4242 {
		t.Errorf("expected thread ID 4242, got %d", bt.ThreadID)
	}
	if bt.Registers["rip"] != 0x00401142 {
		t.Errorf("expected RIP 0x00401142, got 0x%x", bt.Registers["rip"])
	}
	if bt.Registers["rsp"] != 0x7ffeef00 {
		t.Errorf("expected RSP 0x7ffeef00, got 0x%x", bt.Registers["rsp"])
	}
	if len(bt.Frames) == 0 {
		t.Errorf("expected at least 1 stack frame from RIP")
	}
}

func TestParseCoreDump_Corrupted(t *testing.T) {
	// Empty data
	_, err := ParseCoreDumpOrTrace([]byte{})
	if err == nil {
		t.Errorf("expected error for empty data")
	}

	// Truncated ELF header
	_, err = ParseCoreDumpOrTrace([]byte{0x7f, 'E', 'L', 'F', 0x02, 0x01})
	if err == nil {
		t.Errorf("expected error for truncated ELF header")
	}
}

// buildSyntheticELFCore builds a valid minimal 64-bit ELF core dump with a PT_NOTE segment.
func buildSyntheticELFCore(signalNum, pid int, rip, rsp, faultAddr uint64) []byte {
	buf := new(bytes.Buffer)

	// Note segment data
	noteBuf := new(bytes.Buffer)

	// 1. NT_PRSTATUS note
	prstatus := make([]byte, 336)
	binary.LittleEndian.PutUint32(prstatus[0:4], uint32(signalNum)) // si_signo
	binary.LittleEndian.PutUint32(prstatus[32:36], uint32(pid))    // pr_pid
	// registers at offset 112
	regSlice := prstatus[112:]
	binary.LittleEndian.PutUint64(regSlice[128:136], rip) // rip
	binary.LittleEndian.PutUint64(regSlice[152:160], rsp) // rsp

	// Write note header
	noteName := []byte("CORE\x00")
	namePad := (len(noteName) + 3) &^ 3
	paddedName := make([]byte, namePad)
	copy(paddedName, noteName)

	binary.Write(noteBuf, binary.LittleEndian, uint32(len(noteName)))
	binary.Write(noteBuf, binary.LittleEndian, uint32(len(prstatus)))
	binary.Write(noteBuf, binary.LittleEndian, uint32(1)) // NT_PRSTATUS
	noteBuf.Write(paddedName)
	noteBuf.Write(prstatus)

	// 2. NT_SIGINFO note (type 0x53494749)
	siginfo := make([]byte, 128)
	binary.LittleEndian.PutUint32(siginfo[0:4], uint32(signalNum))
	binary.LittleEndian.PutUint64(siginfo[16:24], faultAddr)

	binary.Write(noteBuf, binary.LittleEndian, uint32(len(noteName)))
	binary.Write(noteBuf, binary.LittleEndian, uint32(len(siginfo)))
	binary.Write(noteBuf, binary.LittleEndian, uint32(0x53494749))
	noteBuf.Write(paddedName)
	noteBuf.Write(siginfo)

	noteBytes := noteBuf.Bytes()

	// ELF Header (64 bytes)
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], []byte{0x7f, 'E', 'L', 'F'})
	elfHeader[4] = 2 // 64-bit
	elfHeader[5] = 1 // Little-endian
	elfHeader[6] = 1 // Version
	elfHeader[7] = 0 // System V ABI
	binary.LittleEndian.PutUint16(elfHeader[16:18], 4)  // ET_CORE
	binary.LittleEndian.PutUint16(elfHeader[18:20], 62) // x86-64
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)  // Version
	binary.LittleEndian.PutUint64(elfHeader[32:40], 64) // e_phoff (immediately following ELF header)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64) // e_ehsize
	binary.LittleEndian.PutUint16(elfHeader[54:56], 56) // e_phentsize
	binary.LittleEndian.PutUint16(elfHeader[56:58], 1)  // e_phnum (1 program header: PT_NOTE)

	// Program Header for PT_NOTE (56 bytes)
	progHeader := make([]byte, 56)
	binary.LittleEndian.PutUint32(progHeader[0:4], 4)             // p_type: PT_NOTE (4)
	binary.LittleEndian.PutUint32(progHeader[4:8], 4)             // p_flags: PF_R (4)
	binary.LittleEndian.PutUint64(progHeader[8:16], 120)          // p_offset: 64 + 56 = 120
	binary.LittleEndian.PutUint64(progHeader[32:40], uint64(len(noteBytes))) // p_filesz
	binary.LittleEndian.PutUint64(progHeader[40:48], uint64(len(noteBytes))) // p_memsz

	buf.Write(elfHeader)
	buf.Write(progHeader)
	buf.Write(noteBytes)

	return buf.Bytes()
}
