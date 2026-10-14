package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCreateExec_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/containers/web-app/exec") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var cfg ExecConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			t.Fatalf("failed decoding request body: %v", err)
		}
		if len(cfg.Cmd) == 0 || cfg.Cmd[0] != "/bin/sh" {
			t.Errorf("unexpected cmd: %v", cfg.Cmd)
		}
		if !cfg.Tty || !cfg.AttachStdout {
			t.Errorf("expected tty and stdout attached")
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "exec-abc123xyz"})
	}))
	defer ts.Close()

	client := NewCustomClient(ts.Client(), ts.URL)
	execID, err := client.CreateExec(context.Background(), "web-app", DefaultExecConfig())
	if err != nil {
		t.Fatalf("CreateExec failed: %v", err)
	}
	if execID != "exec-abc123xyz" {
		t.Errorf("expected exec-abc123xyz, got %s", execID)
	}
}

func TestCreateExec_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := NewCustomClient(ts.Client(), ts.URL)
	_, err := client.CreateExec(context.Background(), "missing-container", DefaultExecConfig())
	if err == nil || err != ErrContainerNotFound {
		t.Errorf("expected ErrContainerNotFound, got %v", err)
	}
}

func TestCreateExec_InvalidContainerID(t *testing.T) {
	client := NewClient()
	_, err := client.CreateExec(context.Background(), "../invalid/path", DefaultExecConfig())
	if err == nil || err != ErrInvalidContainerID {
		t.Errorf("expected ErrInvalidContainerID, got %v", err)
	}
}

func TestResizeExec_SuccessAndBounds(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/exec/exec-123/resize") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		widthVal := r.URL.Query().Get("w")
		heightVal := r.URL.Query().Get("h")
		if widthVal != "120" || heightVal != "40" {
			t.Errorf("unexpected dimensions: w=%s, h=%s", widthVal, heightVal)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := NewCustomClient(ts.Client(), ts.URL)
	ctx := context.Background()

	// Valid resize
	if err := client.ResizeExec(ctx, "exec-123", 120, 40); err != nil {
		t.Fatalf("ResizeExec failed: %v", err)
	}

	// Invalid dimensions
	if err := client.ResizeExec(ctx, "exec-123", 0, 40); err != ErrInvalidDimensions {
		t.Errorf("expected ErrInvalidDimensions for w=0, got %v", err)
	}
	if err := client.ResizeExec(ctx, "exec-123", 80, 1500); err != ErrInvalidDimensions {
		t.Errorf("expected ErrInvalidDimensions for h=1500, got %v", err)
	}
	if err := client.ResizeExec(ctx, "", 80, 24); err == nil {
		t.Errorf("expected error for empty execID")
	}
}

func TestInspectExec_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/exec/exec-456/json") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		resp := ExecInspectResult{
			ID:          "exec-456",
			Running:     false,
			ExitCode:    0,
			ContainerID: "container-789",
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := NewCustomClient(ts.Client(), ts.URL)
	inspect, err := client.InspectExec(context.Background(), "exec-456")
	if err != nil {
		t.Fatalf("InspectExec failed: %v", err)
	}
	if inspect.ID != "exec-456" || inspect.ExitCode != 0 || inspect.Running {
		t.Errorf("unexpected inspect payload: %+v", inspect)
	}
}

func TestInspectExec_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := NewCustomClient(ts.Client(), ts.URL)
	_, err := client.InspectExec(context.Background(), "missing-exec")
	if err != ErrExecNotFound {
		t.Errorf("expected ErrExecNotFound, got %v", err)
	}
}

func TestStartExecHijack_MockSocket(t *testing.T) {
	// Start a raw TCP listener simulating Docker daemon raw hijack handshake
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind listener: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		// Read HTTP request header
		for {
			line, err := reader.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
		}

		// Respond with 101 UPGRADED
		resp := "HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
		_, _ = io.WriteString(conn, resp)

		// Echo back data or send welcome banner
		_, _ = io.WriteString(conn, "root@container:/# echo ready\r\nready\r\n")

		// Read one line from client
		cmd, _ := reader.ReadString('\n')
		if strings.TrimSpace(cmd) != "" {
			_, _ = io.WriteString(conn, fmt.Sprintf("executed: %s\r\n", strings.TrimSpace(cmd)))
		}
	}()

	addr := fmt.Sprintf("http://%s", listener.Addr().String())
	client := &Client{
		httpClient: &http.Client{Timeout: 2 * time.Second},
		endpoint:   addr,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, reader, err := client.StartExecHijack(ctx, "exec-mock-1")
	if err != nil {
		t.Fatalf("StartExecHijack failed: %v", err)
	}
	defer conn.Close()

	// Read welcome line from stream
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed reading line from upgraded stream: %v", err)
	}
	if !strings.Contains(line, "root@container") {
		t.Errorf("unexpected banner from exec stream: %s", line)
	}

	// Write command
	_, _ = io.WriteString(conn, "ls -la\n")

	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server")
	}
}
