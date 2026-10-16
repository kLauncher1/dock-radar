package ebpf

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DetectProbeMode determines the most capable probe mode supported by the host.
func DetectProbeMode() (ProbeMode, string) {
	kernelVer := runtime.GOOS + " " + runtime.GOARCH

	// 1. Check for Linux native tracing / eBPF debugfs
	if runtime.GOOS == "linux" {
		if verBytes, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			kernelVer = strings.TrimSpace(string(verBytes))
		}

		if _, err := os.Stat("/sys/kernel/debug/tracing"); err == nil {
			return ProbeModeNative, kernelVer
		}
		if _, err := os.Stat("/sys/kernel/tracing"); err == nil {
			return ProbeModeNative, kernelVer
		}

		// 2. Check for Linux procfs socket tables
		if _, err := os.Stat("/proc/net/tcp"); err == nil {
			return ProbeModeProcfs, kernelVer
		}
	}

	// 3. Fallback to synthetic portable tracer (for macOS, Windows, or unprivileged dev environments)
	return ProbeModeSynthetic, kernelVer
}

// ParseProcNetTCP parses a Linux /proc/net/tcp or /proc/net/tcp6 file into SocketFlow records.
func ParseProcNetTCP(content string, isIPv6 bool, containerID, containerName string) ([]SocketFlow, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var flows []SocketFlow

	isHeader := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if isHeader {
			isHeader = false
			continue
		}
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// fields[1] = local_address, fields[2] = rem_address, fields[3] = st
		localAddr, err := parseProcHexAddr(fields[1], isIPv6)
		if err != nil {
			continue
		}

		remoteAddr, err := parseProcHexAddr(fields[2], isIPv6)
		if err != nil {
			continue
		}

		state := parseProcState(fields[3])

		// fields[4] is tx_queue:rx_queue
		var txBytes, rxBytes uint64
		if queueParts := strings.Split(fields[4], ":"); len(queueParts) == 2 {
			if tx, err := strconv.ParseUint(queueParts[0], 16, 64); err == nil {
				txBytes = tx
			}
			if rx, err := strconv.ParseUint(queueParts[1], 16, 64); err == nil {
				rxBytes = rx
			}
		}

		now := time.Now().UTC()
		flow := SocketFlow{
			ContainerID:   containerID,
			ContainerName: containerName,
			Protocol:      "TCP",
			LocalAddr:     localAddr,
			RemoteAddr:    remoteAddr,
			State:         state,
			BytesSent:     txBytes,
			BytesRecv:     rxBytes,
			FirstSeen:     now,
			LastSeen:      now,
		}
		flows = append(flows, flow)
	}

	return flows, scanner.Err()
}

// parseProcHexAddr converts a hex address string (e.g. "0100007F:0050") to "127.0.0.1:80".
func parseProcHexAddr(hexStr string, isIPv6 bool) (string, error) {
	parts := strings.Split(hexStr, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid address format: %s", hexStr)
	}

	portNum, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", fmt.Errorf("invalid port: %w", err)
	}

	rawBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid hex bytes: %w", err)
	}

	if !isIPv6 {
		if len(rawBytes) != 4 {
			return "", fmt.Errorf("unexpected IPv4 byte length: %d", len(rawBytes))
		}
		// Little-endian IPv4 in /proc/net/tcp
		ip := net.IPv4(rawBytes[3], rawBytes[2], rawBytes[1], rawBytes[0])
		return fmt.Sprintf("%s:%d", ip.String(), portNum), nil
	}

	// IPv6 address
	if len(rawBytes) != 16 {
		return "", fmt.Errorf("unexpected IPv6 byte length: %d", len(rawBytes))
	}
	// Swap 32-bit words for little-endian Linux representation
	ipBytes := make([]byte, 16)
	for i := 0; i < 16; i += 4 {
		word := binary.LittleEndian.Uint32(rawBytes[i : i+4])
		binary.BigEndian.PutUint32(ipBytes[i:i+4], word)
	}
	ip := net.IP(ipBytes)
	return fmt.Sprintf("[%s]:%d", ip.String(), portNum), nil
}

// parseProcState maps /proc/net/tcp state hex to standard state names.
func parseProcState(stateHex string) string {
	val, err := strconv.ParseInt(stateHex, 16, 32)
	if err != nil {
		return "UNKNOWN"
	}
	switch val {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSE"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	default:
		return "UNKNOWN"
	}
}

// ReadContainerProcSockets reads TCP sockets from a specific container's net namespace if accessible.
func ReadContainerProcSockets(pid int, containerID, containerName string) ([]SocketFlow, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid container PID %d", pid)
	}

	procPath := filepath.Join("/proc", strconv.Itoa(pid), "net", "tcp")
	data, err := os.ReadFile(procPath)
	if err != nil {
		return nil, err
	}

	return ParseProcNetTCP(string(data), false, containerID, containerName)
}
