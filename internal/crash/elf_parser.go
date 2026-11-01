package crash

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	gdbFrameRegex = regexp.MustCompile(`(?i)^\s*#(\d+)\s+(?:(0x[0-9a-fA-F]+)\s+in\s+)?([^\s(]+)(?:\s*\([^)]*\))?(?:\s+(?:at\s+([^:\s]+):(\d+)|from\s+([^\s]+)))?`)
	goFuncRegex   = regexp.MustCompile(`^([a-zA-Z0-9_\-\.\/\(\)\*]+)\(.*\)$`)
	goFileRegex   = regexp.MustCompile(`^\s*(.+):(\d+)(?:\s+\+0x([0-9a-fA-F]+))?$`)
)

// ParseCoreDumpOrTrace inspects raw bytes, determining whether they represent a binary ELF core
// dump or formatted text backtrace telemetry, returning the extracted execution backtrace.
func ParseCoreDumpOrTrace(data []byte) (Backtrace, error) {
	if len(data) == 0 {
		return Backtrace{}, errors.New("empty crash dump payload")
	}

	// Check for ELF magic: 0x7F 'E' 'L' 'F'
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return parseELFCore(data)
	}

	// Fallback to text stack backtrace parser
	return ParseTextBacktrace(string(data))
}

// parseELFCore parses PT_NOTE segments in an ELF core dump to extract crash signals, registers, and stack frames.
func parseELFCore(data []byte) (Backtrace, error) {
	r := bytes.NewReader(data)
	f, err := elf.NewFile(r)
	if err != nil {
		return Backtrace{}, fmt.Errorf("invalid elf structure: %w", err)
	}
	defer f.Close()

	bt := Backtrace{
		Registers: make(map[string]uint64),
		Frames:    make([]StackFrame, 0),
	}

	// Search program headers for PT_NOTE
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_NOTE {
			continue
		}

		noteData := make([]byte, prog.Filesz)
		n, err := prog.ReadAt(noteData, 0)
		if err != nil && n == 0 {
			continue
		}
		noteData = noteData[:n]

		offset := 0
		for offset+12 <= len(noteData) {
			namesz := binary.LittleEndian.Uint32(noteData[offset : offset+4])
			descsz := binary.LittleEndian.Uint32(noteData[offset+4 : offset+8])
			nType := binary.LittleEndian.Uint32(noteData[offset+8 : offset+12])
			offset += 12

			// Names are aligned to 4 bytes
			nameAligned := (int(namesz) + 3) &^ 3
			if offset+nameAligned > len(noteData) {
				break
			}
			name := strings.TrimRight(string(noteData[offset:offset+int(namesz)]), "\x00")
			offset += nameAligned

			descAligned := (int(descsz) + 3) &^ 3
			if offset+int(descsz) > len(noteData) {
				break
			}
			desc := noteData[offset : offset+int(descsz)]
			offset += descAligned

			if name == "CORE" || name == "LINUX" {
				switch nType {
				case 1: // NT_PRSTATUS
					parsePRStatus(desc, &bt)
				case 0x53494749: // NT_SIGINFO
					if len(desc) >= 24 {
						bt.SignalNum = int(binary.LittleEndian.Uint32(desc[0:4]))
						bt.Signal = SignalName(bt.SignalNum)
						bt.FaultAddress = binary.LittleEndian.Uint64(desc[16:24])
					}
				}
			}
		}
	}

	if bt.Signal == "" && bt.SignalNum != 0 {
		bt.Signal = SignalName(bt.SignalNum)
	}

	// Synthesize initial top stack frame from instruction pointer if available
	if rip, ok := bt.Registers["rip"]; ok && rip != 0 {
		bt.Frames = append(bt.Frames, StackFrame{
			FrameIndex: 0,
			IP:         rip,
			Function:   fmt.Sprintf("0x%016x", rip),
			Module:     "app",
			Offset:     rip,
		})
	}

	// Inspect stack segment from PT_LOAD to extract callers
	scanStackMemory(f, &bt)

	return bt, nil
}

// parsePRStatus extracts signal number, thread ID, and registers from an NT_PRSTATUS note descriptor.
func parsePRStatus(desc []byte, bt *Backtrace) {
	if len(desc) < 144 {
		return
	}
	// pr_info.si_signo is at offset 0
	if bt.SignalNum == 0 {
		bt.SignalNum = int(binary.LittleEndian.Uint32(desc[0:4]))
		bt.Signal = SignalName(bt.SignalNum)
	}
	// pr_pid is at offset 32
	if bt.ThreadID == 0 {
		bt.ThreadID = int(binary.LittleEndian.Uint32(desc[32:36]))
	}

	// x86_64 user_regs_struct begins at offset 112
	regBytes := desc[112:]
	if len(regBytes) >= 168 {
		bt.Registers["r15"] = binary.LittleEndian.Uint64(regBytes[0:8])
		bt.Registers["r14"] = binary.LittleEndian.Uint64(regBytes[8:16])
		bt.Registers["r13"] = binary.LittleEndian.Uint64(regBytes[16:24])
		bt.Registers["r12"] = binary.LittleEndian.Uint64(regBytes[24:32])
		bt.Registers["rbp"] = binary.LittleEndian.Uint64(regBytes[32:40])
		bt.Registers["rbx"] = binary.LittleEndian.Uint64(regBytes[40:48])
		bt.Registers["r11"] = binary.LittleEndian.Uint64(regBytes[48:56])
		bt.Registers["r10"] = binary.LittleEndian.Uint64(regBytes[56:64])
		bt.Registers["r9"] = binary.LittleEndian.Uint64(regBytes[64:72])
		bt.Registers["r8"] = binary.LittleEndian.Uint64(regBytes[72:80])
		bt.Registers["rax"] = binary.LittleEndian.Uint64(regBytes[80:88])
		bt.Registers["rcx"] = binary.LittleEndian.Uint64(regBytes[88:96])
		bt.Registers["rdx"] = binary.LittleEndian.Uint64(regBytes[96:104])
		bt.Registers["rsi"] = binary.LittleEndian.Uint64(regBytes[104:112])
		bt.Registers["rdi"] = binary.LittleEndian.Uint64(regBytes[112:120])
		bt.Registers["rip"] = binary.LittleEndian.Uint64(regBytes[128:136])
		bt.Registers["rsp"] = binary.LittleEndian.Uint64(regBytes[152:160])

		if bt.FaultAddress == 0 && bt.Registers["rip"] != 0 {
			bt.FaultAddress = bt.Registers["rip"]
		}
	}
}

// scanStackMemory reads word values from the stack segment pointed to by RSP, extracting potential call frames.
func scanStackMemory(f *elf.File, bt *Backtrace) {
	rsp, ok := bt.Registers["rsp"]
	if !ok || rsp == 0 {
		return
	}

	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if rsp >= prog.Vaddr && rsp < prog.Vaddr+prog.Memsz {
			// Found stack segment
			readLen := int(prog.Memsz - (rsp - prog.Vaddr))
			if readLen > 4096 {
				readLen = 4096
			}
			stackBuf := make([]byte, readLen)
			n, err := prog.ReadAt(stackBuf, int64(rsp-prog.Vaddr))
			if err != nil && n == 0 {
				return
			}
			stackBuf = stackBuf[:n]

			frameIdx := len(bt.Frames)
			for i := 0; i+8 <= len(stackBuf) && frameIdx < 16; i += 8 {
				ptr := binary.LittleEndian.Uint64(stackBuf[i : i+8])
				// Check if ptr points into an executable code segment
				if isExecutableAddress(f, ptr) {
					bt.Frames = append(bt.Frames, StackFrame{
						FrameIndex: frameIdx,
						IP:         ptr,
						Function:   fmt.Sprintf("sub_%x", ptr),
						Module:     "app",
						Offset:     ptr,
					})
					frameIdx++
				}
			}
			break
		}
	}
}

// isExecutableAddress determines if a virtual address falls within an executable ELF PT_LOAD segment.
func isExecutableAddress(f *elf.File, addr uint64) bool {
	if addr < 0x400000 {
		return false
	}
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD && (prog.Flags&elf.PF_X != 0) {
			if addr >= prog.Vaddr && addr < prog.Vaddr+prog.Memsz {
				return true
			}
		}
	}
	return false
}

// ParseTextBacktrace parses formatted stack backtraces (GDB, LLDB, AddressSanitizer, or Go panics).
func ParseTextBacktrace(text string) (Backtrace, error) {
	bt := Backtrace{
		Registers: make(map[string]uint64),
		Frames:    make([]StackFrame, 0),
	}

	lines := strings.Split(text, "\n")
	var currentFunc string

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		// Detect signals in text header
		if strings.Contains(line, "SIGSEGV") || strings.Contains(line, "segmentation fault") {
			bt.Signal = "SIGSEGV"
			bt.SignalNum = 11
		} else if strings.Contains(line, "SIGABRT") || strings.Contains(line, "abort") {
			bt.Signal = "SIGABRT"
			bt.SignalNum = 6
		} else if strings.Contains(line, "SIGILL") {
			bt.Signal = "SIGILL"
			bt.SignalNum = 4
		} else if strings.Contains(line, "SIGBUS") {
			bt.Signal = "SIGBUS"
			bt.SignalNum = 7
		} else if strings.Contains(line, "SIGFPE") {
			bt.Signal = "SIGFPE"
			bt.SignalNum = 8
		}

		// Parse fault address if present (e.g., "fault address: 0x0")
		if strings.Contains(strings.ToLower(line), "fault address") || strings.Contains(strings.ToLower(line), "address 0x") {
			re := regexp.MustCompile(`(?i)(?:fault\s+address:?\s*|address\s+)(0x[0-9a-fA-F]+)`)
			if m := re.FindStringSubmatch(line); len(m) > 1 {
				if parsed, err := strconv.ParseUint(strings.TrimPrefix(m[1], "0x"), 16, 64); err == nil {
					bt.FaultAddress = parsed
				}
			}
		}

		// Try matching GDB / ASAN backtrace frame: "#0 0x00401234 in main () at main.c:42"
		if m := gdbFrameRegex.FindStringSubmatch(line); len(m) > 0 {
			idx, _ := strconv.Atoi(m[1])
			var ip uint64
			if m[2] != "" {
				ip, _ = strconv.ParseUint(strings.TrimPrefix(m[2], "0x"), 16, 64)
			}
			fn := m[3]
			src := m[4]
			var lineNum int
			if m[5] != "" {
				lineNum, _ = strconv.Atoi(m[5])
			}
			mod := m[6]
			if mod == "" {
				mod = "app"
			}

			bt.Frames = append(bt.Frames, StackFrame{
				FrameIndex: idx,
				IP:         ip,
				Function:   fn,
				Module:     mod,
				SourceFile: src,
				Line:       lineNum,
				Offset:     ip,
			})
			continue
		}

		// Try matching Go panic stack traces
		if m := goFuncRegex.FindStringSubmatch(line); len(m) > 1 {
			currentFunc = m[1]
			continue
		}
		if currentFunc != "" {
			if m := goFileRegex.FindStringSubmatch(line); len(m) > 1 {
				lineNum, _ := strconv.Atoi(m[2])
				var offset uint64
				if m[3] != "" {
					offset, _ = strconv.ParseUint(m[3], 16, 64)
				}
				bt.Frames = append(bt.Frames, StackFrame{
					FrameIndex: len(bt.Frames),
					IP:         offset,
					Function:   currentFunc,
					Module:     "go",
					SourceFile: m[1],
					Line:       lineNum,
					Offset:     offset,
				})
				currentFunc = ""
				continue
			}
		}
	}

	if bt.Signal == "" {
		bt.Signal = "SIGSEGV"
		bt.SignalNum = 11
	}

	return bt, nil
}
