package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var (
	// ErrInvalidContainerID denotes malformed container identifiers.
	ErrInvalidContainerID = errors.New("invalid container identifier: must be 1-128 alphanumeric characters with optional '.', '_', or '-'")
	// ErrContainerNotFound denotes when Docker returns 404 for the requested container.
	ErrContainerNotFound = errors.New("container not found")
	// ErrDaemonUnreachable denotes failure to communicate with Docker daemon.
	ErrDaemonUnreachable = errors.New("docker daemon is unreachable or socket offline")

	// containerIDRegex strictly limits container IDs and names to safe characters.
	containerIDRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
)

// ValidateContainerID verifies that the container ID or name conforms to Docker specifications.
func ValidateContainerID(id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" || len(trimmed) > 128 {
		return ErrInvalidContainerID
	}
	if !containerIDRegex.MatchString(trimmed) {
		return ErrInvalidContainerID
	}
	return nil
}

// NewCustomClient allows instantiating a Client with custom HTTP transport (useful for tests and proxies).
func NewCustomClient(httpClient *http.Client, endpoint string) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &Client{
		httpClient: httpClient,
		endpoint:   endpoint,
	}
}

// RestartContainer issues a restart command to Docker daemon for the specified container.
func (c *Client) RestartContainer(ctx context.Context, id string, timeoutSeconds int) error {
	if err := ValidateContainerID(id); err != nil {
		return err
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}

	reqURL := fmt.Sprintf("http://localhost/v1.43/containers/%s/restart?t=%d", id, timeoutSeconds)
	if runtime.GOOS == "windows" {
		reqURL = fmt.Sprintf("%s/v1.43/containers/%s/restart?t=%d", c.endpoint, id, timeoutSeconds)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create restart request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrContainerNotFound
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("docker returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

// StopContainer issues a stop command to Docker daemon for the specified container.
func (c *Client) StopContainer(ctx context.Context, id string, timeoutSeconds int) error {
	if err := ValidateContainerID(id); err != nil {
		return err
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}

	reqURL := fmt.Sprintf("http://localhost/v1.43/containers/%s/stop?t=%d", id, timeoutSeconds)
	if runtime.GOOS == "windows" {
		reqURL = fmt.Sprintf("%s/v1.43/containers/%s/stop?t=%d", c.endpoint, id, timeoutSeconds)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create stop request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusNotModified:
		// 304 Not Modified means container is already stopped, which is considered successful completion.
		return nil
	case http.StatusNotFound:
		return ErrContainerNotFound
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("docker returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}
