package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	// ErrExecNotFound indicates Docker exec instance does not exist.
	ErrExecNotFound = errors.New("exec instance not found")
	// ErrExecAlreadyRunning indicates exec instance is already active.
	ErrExecAlreadyRunning = errors.New("exec instance is already running")
	// ErrInvalidDimensions indicates invalid terminal width or height.
	ErrInvalidDimensions = errors.New("terminal dimensions must be between 1 and 1000")
)

// ExecConfig specifies configuration for creating an interactive container exec instance.
type ExecConfig struct {
	Cmd          []string `json:"Cmd,omitempty"`
	Env          []string `json:"Env,omitempty"`
	User         string   `json:"User,omitempty"`
	WorkingDir   string   `json:"WorkingDir,omitempty"`
	Privileged   bool     `json:"Privileged,omitempty"`
	Tty          bool     `json:"Tty"`
	AttachStdin  bool     `json:"AttachStdin"`
	AttachStdout bool     `json:"AttachStdout"`
	AttachStderr bool     `json:"AttachStderr"`
	ReadOnly     bool     `json:"ReadOnly,omitempty"`
}

// DefaultExecConfig returns standard interactive shell execution parameters.
func DefaultExecConfig() ExecConfig {
	return ExecConfig{
		Cmd:          []string{"/bin/sh"},
		Env:          []string{"TERM=xterm-256color"},
		Tty:          true,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
	}
}

// ExecInspectResult reflects the current status and exit code of an exec instance.
type ExecInspectResult struct {
	ID          string `json:"ID"`
	Running     bool   `json:"Running"`
	ExitCode    int    `json:"ExitCode"`
	ContainerID string `json:"ContainerID"`
	OpenStdin   bool   `json:"OpenStdin"`
	OpenStdout  bool   `json:"OpenStdout"`
	OpenStderr  bool   `json:"OpenStderr"`
	CanRemove   bool   `json:"CanRemove"`
}

// CreateExec initializes an exec instance on the target container.
func (c *Client) CreateExec(ctx context.Context, containerID string, cfg ExecConfig) (string, error) {
	if err := ValidateContainerID(containerID); err != nil {
		return "", err
	}

	if len(cfg.Cmd) == 0 {
		cfg.Cmd = []string{"/bin/sh"}
	}
	if len(cfg.Env) == 0 {
		cfg.Env = []string{"TERM=xterm-256color"}
	}
	cfg.Tty = true
	cfg.AttachStdout = true
	cfg.AttachStderr = true
	if !cfg.ReadOnly {
		cfg.AttachStdin = true
	}

	payload, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to encode exec configuration: %w", err)
	}

	reqURL := fmt.Sprintf("%s/v1.43/containers/%s/exec", c.BaseURL(), containerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create exec request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", ErrContainerNotFound
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("docker engine returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode exec creation response: %w", err)
	}
	if result.ID == "" {
		return "", errors.New("docker returned empty exec ID")
	}

	return result.ID, nil
}

// DialDaemonRaw establishes a raw socket connection to the Docker daemon.
func (c *Client) DialDaemonRaw(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	if strings.HasPrefix(c.endpoint, "http://") || strings.HasPrefix(c.endpoint, "https://") {
		parsed, err := url.Parse(c.endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid daemon endpoint URL: %w", err)
		}
		host := parsed.Host
		if !strings.Contains(host, ":") {
			if parsed.Scheme == "https" {
				host += ":443"
			} else {
				host += ":80"
			}
		}
		return dialer.DialContext(ctx, "tcp", host)
	}
	return dialer.DialContext(ctx, "unix", c.endpoint)
}

// StartExecHijack starts the exec instance and hijacks the raw duplex stream.
func (c *Client) StartExecHijack(ctx context.Context, execID string) (net.Conn, *bufio.Reader, error) {
	trimmedID := strings.TrimSpace(execID)
	if trimmedID == "" {
		return nil, nil, errors.New("exec ID cannot be empty")
	}

	conn, err := c.DialDaemonRaw(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}

	startPayload := `{"Detach":false,"Tty":true}`
	httpReq := fmt.Sprintf(
		"POST /v1.43/exec/%s/start HTTP/1.1\r\n"+
			"Host: localhost\r\n"+
			"Content-Type: application/json\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: tcp\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		trimmedID,
		len(startPayload),
		startPayload,
	)

	if _, err := io.WriteString(conn, httpReq); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("failed to write exec start request: %w", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("failed to read exec start response: %w", err)
	}

	if !strings.Contains(statusLine, "101") && !strings.Contains(statusLine, "200") {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("docker exec start failed: %s", strings.TrimSpace(statusLine))
	}

	// Consume remaining HTTP response headers until CRLF CRLF
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("failed reading exec handshake headers: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	return conn, reader, nil
}

// ResizeExec dynamically changes the terminal window dimensions for an active exec session.
func (c *Client) ResizeExec(ctx context.Context, execID string, width, height int) error {
	trimmedID := strings.TrimSpace(execID)
	if trimmedID == "" {
		return errors.New("exec ID cannot be empty")
	}
	if width < 1 || width > 1000 || height < 1 || height > 1000 {
		return ErrInvalidDimensions
	}

	reqURL := fmt.Sprintf("%s/v1.43/exec/%s/resize?w=%d&h=%d", c.BaseURL(), trimmedID, width, height)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create resize request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrExecNotFound
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("docker engine returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return nil
}

// InspectExec retrieves the status, execution state, and exit code of an exec instance.
func (c *Client) InspectExec(ctx context.Context, execID string) (*ExecInspectResult, error) {
	trimmedID := strings.TrimSpace(execID)
	if trimmedID == "" {
		return nil, errors.New("exec ID cannot be empty")
	}

	reqURL := fmt.Sprintf("%s/v1.43/exec/%s/json", c.BaseURL(), trimmedID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create inspect request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrExecNotFound
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("docker engine returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var inspect ExecInspectResult
	if err := json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return nil, fmt.Errorf("failed to decode exec inspection: %w", err)
	}

	return &inspect, nil
}
