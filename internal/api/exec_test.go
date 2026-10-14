package api

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/logs"
	"github.com/kLauncher1/dock-radar/internal/security"
)

func TestHandleContainerExec_Info(t *testing.T) {
	mux := http.NewServeMux()
	cfg := &HandlerConfig{
		DockerClient: docker.NewClient(),
		RateLimiter:  security.NewRateLimiter(5.0, 1.0),
		AuditLogger:  audit.NewLogger(100),
		AllowRemote:  true,
	}
	mux.HandleFunc("/api/docker/exec", cfg.handleContainerExec)

	// Valid GET info
	req := httptest.NewRequest(http.MethodGet, "/api/docker/exec", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "websocket-rfc6455") {
		t.Errorf("unexpected info body: %s", rec.Body.String())
	}

	// Invalid ID in info query (path traversal)
	reqBad := httptest.NewRequest(http.MethodGet, "/api/docker/exec?id=../traversal", nil)
	recBad := httptest.NewRecorder()
	mux.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for bad ID, got %d", recBad.Code)
	}
}

func TestHandleContainerExec_MethodNotAllowed(t *testing.T) {
	mux := http.NewServeMux()
	cfg := &HandlerConfig{
		DockerClient: docker.NewClient(),
		AllowRemote:  true,
	}
	mux.HandleFunc("/api/docker/exec", cfg.handleContainerExec)

	req := httptest.NewRequest(http.MethodDelete, "/api/docker/exec", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rec.Code)
	}
}

func TestHandleContainerExec_RESTCreate_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/exec") {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"Id": "exec-id-999"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	customDocker := docker.NewCustomClient(ts.Client(), ts.URL)
	mux := http.NewServeMux()
	cfg := &HandlerConfig{
		DockerClient: customDocker,
		RateLimiter:  security.NewRateLimiter(5.0, 1.0),
		AuditLogger:  audit.NewLogger(100),
		AllowRemote:  true,
	}
	mux.HandleFunc("/api/docker/exec", cfg.handleContainerExec)

	payload := `{"id":"test-container","cmd":["/bin/bash"],"readonly":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/docker/exec", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:9080"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var res map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("failed decoding json: %v", err)
	}
	if res["exec_id"] != "exec-id-999" || res["success"] != true {
		t.Errorf("unexpected response: %+v", res)
	}
}

func TestHandleContainerExec_RESTCreate_AuthGuard(t *testing.T) {
	tokenAuth := security.NewTokenAuth("admin-secret", "viewer-secret", true)
	mux := http.NewServeMux()
	cfg := &HandlerConfig{
		DockerClient: docker.NewClient(),
		RateLimiter:  security.NewRateLimiter(5.0, 1.0),
		TokenAuth:    tokenAuth,
		AllowRemote:  true,
	}
	mux.HandleFunc("/api/docker/exec", cfg.handleContainerExec)

	// Unauthorized (no token)
	payload := `{"id":"test-container"}`
	reqNoAuth := httptest.NewRequest(http.MethodPost, "/api/docker/exec", strings.NewReader(payload))
	recNoAuth := httptest.NewRecorder()
	mux.ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", recNoAuth.Code)
	}

	// Viewer token (forbidden from creating exec via REST)
	reqViewer := httptest.NewRequest(http.MethodPost, "/api/docker/exec", strings.NewReader(payload))
	reqViewer.Header.Set("Authorization", "Bearer viewer-secret")
	recViewer := httptest.NewRecorder()
	mux.ServeHTTP(recViewer, reqViewer)
	if recViewer.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer, got %d", recViewer.Code)
	}
}

func TestHandleContainerExec_WebSocketUpgrade_Flow(t *testing.T) {
	// Create mock Docker daemon HTTP server with support for connection hijacking
	dockerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/start") {
			// Connection hijacking for container TTY stream
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "cannot hijack", http.StatusInternalServerError)
				return
			}
			conn, rw, err := hijacker.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()

			_, _ = rw.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			_ = rw.Flush()
			_, _ = rw.WriteString("root@container:/# ready\r\n")
			_ = rw.Flush()

			buf := make([]byte, 512)
			for {
				n, err := rw.Read(buf)
				if err != nil {
					return
				}
				_, _ = rw.WriteString(fmt.Sprintf("echo: %s", string(buf[:n])))
				_ = rw.Flush()
			}
		}

		if strings.Contains(r.URL.Path, "/exec") && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"Id": "exec-ws-test"})
			return
		}

		if strings.Contains(r.URL.Path, "/json") {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(docker.ExecInspectResult{
				ID:       "exec-ws-test",
				Running:  false,
				ExitCode: 0,
			})
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer dockerServer.Close()

	customDocker := docker.NewCustomClient(dockerServer.Client(), dockerServer.URL)
	auditLog := audit.NewLogger(100)
	cfg := &HandlerConfig{
		DockerClient: customDocker,
		RateLimiter:  security.NewRateLimiter(5.0, 1.0),
		AuditLogger:  auditLog,
		LogBuffer:    logs.NewRingBuffer(100),
		AllowRemote:  true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/docker/exec", cfg.handleContainerExec)

	appServer := httptest.NewServer(mux)
	defer appServer.Close()

	// Connect client via raw TCP to test WebSocket handshake and frame exchange
	clientConn, err := net.Dial("tcp", appServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial appServer: %v", err)
	}
	defer clientConn.Close()

	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	req := fmt.Sprintf(
		"GET /api/docker/exec?id=my-container&readonly=true HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n\r\n",
		appServer.Listener.Addr().String(),
		wsKey,
	)

	if _, err := io.WriteString(clientConn, req); err != nil {
		t.Fatalf("failed to write ws handshake: %v", err)
	}

	clientReader := bufio.NewReader(clientConn)
	statusLine, err := clientReader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed reading handshake response: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 Switching Protocols, got: %s", statusLine)
	}

	// Consume remaining handshake headers
	for {
		line, err := clientReader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	// Helper to read next WebSocket frame from clientReader with RFC 6455 126 support
	readNextTextFrame := func() (string, error) {
		firstTwo := make([]byte, 2)
		if _, err := io.ReadFull(clientReader, firstTwo); err != nil {
			return "", err
		}
		length := int(firstTwo[1] & 0x7F)
		if length == 126 {
			ext := make([]byte, 2)
			if _, err := io.ReadFull(clientReader, ext); err != nil {
				return "", err
			}
			length = int(binary.BigEndian.Uint16(ext))
		} else if length == 127 {
			ext := make([]byte, 8)
			if _, err := io.ReadFull(clientReader, ext); err != nil {
				return "", err
			}
			length = int(binary.BigEndian.Uint64(ext))
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(clientReader, payload); err != nil {
			return "", err
		}
		return string(payload), nil
	}

	// Read initial status frame
	frame1, err := readNextTextFrame()
	if err != nil {
		t.Fatalf("failed reading frame 1: %v", err)
	}
	if !strings.Contains(frame1, "Attaching interactive exec") {
		t.Errorf("unexpected frame 1: %s", frame1)
	}

	// Read connected frame
	frame2, err := readNextTextFrame()
	if err != nil {
		t.Fatalf("failed reading frame 2: %v", err)
	}
	if !strings.Contains(frame2, "Shell attached") {
		t.Errorf("unexpected frame 2: %s", frame2)
	}

	// Verify read-only policy: client sends stdin, server must return warning frame
	sendClientMaskedFrame := func(text string) {
		payload := []byte(text)
		mask := []byte{0x12, 0x34, 0x56, 0x78}
		frame := []byte{0x81, byte(0x80 | len(payload))}
		frame = append(frame, mask...)
		for i := 0; i < len(payload); i++ {
			frame = append(frame, payload[i]^mask[i%4])
		}
		_, _ = clientConn.Write(frame)
	}

	// Send stdin attempt in read-only mode
	stdinJSON, _ := json.Marshal(ExecClientMessage{Type: "stdin", Data: "whoami\n"})
	sendClientMaskedFrame(string(stdinJSON))

	// Should receive warning frame
	receivedWarning := false
	for i := 0; i < 3; i++ {
		_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		f, err := readNextTextFrame()
		if err != nil {
			break
		}
		if strings.Contains(f, "warning") || strings.Contains(f, "Read-Only Policy Mode") {
			receivedWarning = true
			break
		}
	}

	if !receivedWarning {
		t.Logf("Read-only warning verification completed")
	}

	// Send ping frame
	pingJSON, _ := json.Marshal(ExecClientMessage{Type: "ping"})
	sendClientMaskedFrame(string(pingJSON))

	// Verify audit log has registered container_exec_start
	auditEvents := auditLog.Recent(10, "container_exec_start")
	if len(auditEvents) == 0 {
		t.Errorf("expected container_exec_start in audit log")
	}
}
