package ebpf

import (
	"testing"
)

func TestParseProcHexAddr_IPv4(t *testing.T) {
	// "0100007F:0050" -> 127.0.0.1:80
	addr, err := parseProcHexAddr("0100007F:0050", false)
	if err != nil {
		t.Fatalf("Failed to parse IPv4 address: %v", err)
	}
	if addr != "127.0.0.1:80" {
		t.Fatalf("Expected 127.0.0.1:80, got %s", addr)
	}

	// "020011AC:1F90" -> 172.17.0.2:8080 (0xAC=172, 0x11=17, 0x00=0, 0x02=2; 0x1F90=8080)
	addr, err = parseProcHexAddr("020011AC:1F90", false)
	if err != nil {
		t.Fatalf("Failed to parse IPv4 address: %v", err)
	}
	if addr != "172.17.0.2:8080" {
		t.Fatalf("Expected 172.17.0.2:8080, got %s", addr)
	}
}

func TestParseProcState(t *testing.T) {
	if s := parseProcState("01"); s != "ESTABLISHED" {
		t.Fatalf("Expected ESTABLISHED, got %s", s)
	}
	if s := parseProcState("0A"); s != "LISTEN" {
		t.Fatalf("Expected LISTEN, got %s", s)
	}
	if s := parseProcState("06"); s != "TIME_WAIT" {
		t.Fatalf("Expected TIME_WAIT, got %s", s)
	}
}

func TestParseProcNetTCP_Vector(t *testing.T) {
	sampleProcTCP := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 020011AC:1F90 0100007F:C000 01 00000100:00000200 00:00000000 00000000  1000        0 12346 1 0000000000000000 100 0 0 10 0
`

	flows, err := ParseProcNetTCP(sampleProcTCP, false, "c-nginx", "nginx-proxy")
	if err != nil {
		t.Fatalf("Failed to parse sample /proc/net/tcp: %v", err)
	}

	if len(flows) != 2 {
		t.Fatalf("Expected 2 flows, got %d", len(flows))
	}

	// First flow: LISTEN on 127.0.0.1:80
	if flows[0].LocalAddr != "127.0.0.1:80" || flows[0].State != "LISTEN" {
		t.Fatalf("Flow 0 mismatch: %s / %s", flows[0].LocalAddr, flows[0].State)
	}

	// Second flow: ESTABLISHED on 172.17.0.2:8080 -> 127.0.0.1:49152 (0xC000 = 49152)
	if flows[1].State != "ESTABLISHED" || flows[1].LocalAddr != "172.17.0.2:8080" {
		t.Fatalf("Flow 1 mismatch: %s / %s", flows[1].LocalAddr, flows[1].State)
	}
	if flows[1].BytesSent != 0x100 || flows[1].BytesRecv != 0x200 {
		t.Fatalf("Queue byte counters mismatch: sent=%d, recv=%d", flows[1].BytesSent, flows[1].BytesRecv)
	}
}

func TestDetectProbeMode(t *testing.T) {
	mode, kernelVer := DetectProbeMode()
	if mode == "" {
		t.Fatal("Expected non-empty ProbeMode")
	}
	if kernelVer == "" {
		t.Fatal("Expected non-empty kernelVer")
	}
}
