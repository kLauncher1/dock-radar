package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// ContainerSummary holds light-weight container details.
type ContainerSummary struct {
	ID      string            `json:"id"`
	Names   []string          `json:"names"`
	Image   string            `json:"image"`
	Status  string            `json:"status"`
	State   string            `json:"state"`
	Created int64             `json:"created"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// DaemonStatus describes Docker daemon availability.
type DaemonStatus struct {
	Available     bool               `json:"available"`
	Endpoint      string             `json:"endpoint"`
	Error         string             `json:"error,omitempty"`
	Containers    []ContainerSummary `json:"containers"`
	TotalCount    int                `json:"total_count"`
	RunningCount  int                `json:"running_count"`
	CheckedAt     time.Time          `json:"checked_at"`
}

// Client wraps Docker engine communication over Unix socket or HTTP.
type Client struct {
	httpClient *http.Client
	endpoint   string
}

// BaseURL returns the HTTP base URL for Docker daemon requests.
func (c *Client) BaseURL() string {
	if strings.HasPrefix(c.endpoint, "http://") || strings.HasPrefix(c.endpoint, "https://") {
		return strings.TrimRight(c.endpoint, "/")
	}
	return "http://localhost"
}

// NewClient initializes a Docker client based on operating system socket paths.
func NewClient() *Client {
	endpoint := "/var/run/docker.sock"
	if runtime.GOOS == "windows" {
		endpoint = "http://localhost:2375"
	}

	dialer := &net.Dialer{Timeout: 800 * time.Millisecond}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, proto, addr string) (net.Conn, error) {
			if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
				return dialer.DialContext(ctx, proto, addr)
			}
			return dialer.DialContext(ctx, "unix", endpoint)
		},
		DisableKeepAlives: true,
	}

	return &Client{
		httpClient: &http.Client{Transport: transport, Timeout: 1200 * time.Millisecond},
		endpoint:   endpoint,
	}
}

// InspectContainers queries the active container list with fallback for offline daemons.
func (c *Client) InspectContainers() DaemonStatus {
	status := DaemonStatus{
		Available:  false,
		Endpoint:   c.endpoint,
		Containers: []ContainerSummary{},
		CheckedAt:  time.Now().UTC(),
	}

	reqURL := fmt.Sprintf("%s/v1.43/containers/json?all=1", c.BaseURL())

	resp, err := c.httpClient.Get(reqURL)
	if err != nil {
		status.Error = fmt.Sprintf("daemon offline or socket unreachable: %v", err)
		return status
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		status.Error = fmt.Sprintf("docker engine returned HTTP %d", resp.StatusCode)
		return status
	}

	var rawContainers []ContainerSummary
	if err := json.NewDecoder(resp.Body).Decode(&rawContainers); err != nil {
		status.Error = fmt.Sprintf("failed to decode container payload: %v", err)
		return status
	}

	running := 0
	for _, c := range rawContainers {
		if c.State == "running" {
			running++
		}
	}

	status.Available = true
	status.Containers = rawContainers
	status.TotalCount = len(rawContainers)
	status.RunningCount = running
	return status
}
