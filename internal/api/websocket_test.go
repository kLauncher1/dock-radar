package api

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestComputeSecWebSocketAccept_RFC6455Vector(t *testing.T) {
	// Official test vector from RFC 6455 Section 1.3
	clientKey := "dGhlIHNhbXBsZSBub25jZQ=="
	expectedAccept := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

	actual := ComputeSecWebSocketAccept(clientKey)
	if actual != expectedAccept {
		t.Fatalf("ComputeSecWebSocketAccept(%q) = %q, want %q", clientKey, actual, expectedAccept)
	}
}

func TestUpgradeWebSocket_DirectExchange(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := UpgradeWebSocket(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer ws.Close()

		// Read client frame
		op, payload, err := ws.ReadFrame()
		if err != nil {
			t.Errorf("server read frame error: %v", err)
			return
		}
		if string(payload) != "hello server" {
			t.Errorf("server got unexpected payload: %s", string(payload))
		}

		// Echo back
		if err := ws.WriteTextMessage([]byte("echo: " + string(payload))); err != nil {
			t.Errorf("server write text message error: %v", err)
		}

		_ = op
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	// Dial TCP directly to perform authentic RFC 6455 handshake
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial test server: %v", err)
	}
	defer conn.Close()

	req := "GET / HTTP/1.1\r\n" +
		"Host: " + server.Listener.Addr().String() + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("failed to send handshake request: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read handshake response: %v", err)
	}
	if !strings.Contains(statusLine, "101 Switching Protocols") {
		t.Fatalf("expected 101 Switching Protocols, got: %s", statusLine)
	}

	// Consume remaining handshake headers until empty line
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("failed to read header: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Send masked client text frame: "hello server"
	payload := []byte("hello server")
	mask := []byte{0x12, 0x34, 0x56, 0x78}
	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i] ^ mask[i%4]
	}

	clientFrame := []byte{0x81, byte(0x80 | len(payload))}
	clientFrame = append(clientFrame, mask...)
	clientFrame = append(clientFrame, maskedPayload...)

	if _, err := conn.Write(clientFrame); err != nil {
		t.Fatalf("failed to write client frame: %v", err)
	}

	// Read server response frame (unmasked from server)
	header := make([]byte, 2)
	if _, err := reader.Read(header); err != nil {
		t.Fatalf("failed to read server frame header: %v", err)
	}
	if header[0] != 0x81 {
		t.Fatalf("expected opcode 0x81 text frame, got 0x%x", header[0])
	}
	respLen := int(header[1] & 0x7F)
	respPayload := make([]byte, respLen)
	if _, err := reader.Read(respPayload); err != nil {
		t.Fatalf("failed to read server response payload: %v", err)
	}

	expectedResp := "echo: hello server"
	if string(respPayload) != expectedResp {
		t.Fatalf("expected %q, got %q", expectedResp, string(respPayload))
	}
}
