package rolling

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/docker"
)

// ReadinessProber evaluates container readiness using Docker daemon inspection and HTTP probes.
type ReadinessProber struct {
	dockerClient *docker.Client
	httpClient   *http.Client
}

// NewReadinessProber constructs a readiness prober with bounded timeouts.
func NewReadinessProber(dockerClient *docker.Client, httpClient *http.Client) *ReadinessProber {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 2 * time.Second,
		}
	}
	return &ReadinessProber{
		dockerClient: dockerClient,
		httpClient:   httpClient,
	}
}

// WaitForReady polls the container until it satisfies readiness criteria or times out.
func (rp *ReadinessProber) WaitForReady(ctx context.Context, containerID string, cfg RollingPlanConfig) error {
	timeout := time.Duration(cfg.ProbeTimeoutSec) * time.Second
	interval := time.Duration(cfg.ProbeIntervalSec) * time.Second
	if interval < 500*time.Millisecond {
		interval = 500 * time.Millisecond
	}

	deadline := time.Now().Add(timeout)
	expectedHTTP := cfg.ExpectedHTTPStatus
	if expectedHTTP <= 0 {
		expectedHTTP = http.StatusOK
	}

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("readiness probe timed out after %s for container %s", timeout, containerID)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Stage 1: Inspect container status from Docker engine
		daemonStatus := rp.dockerClient.InspectContainers()
		var found *docker.ContainerSummary
		for _, c := range daemonStatus.Containers {
			if c.ID == containerID || strings.HasPrefix(c.ID, containerID) {
				found = &c
				break
			}
			for _, name := range c.Names {
				if strings.TrimPrefix(name, "/") == containerID {
					found = &c
					break
				}
			}
		}

		if found != nil {
			stateLower := strings.ToLower(found.State)
			statusLower := strings.ToLower(found.Status)

			// Fast abort on crashed states
			if stateLower == "exited" || stateLower == "dead" {
				return fmt.Errorf("container is in '%s' state with status: %s", stateLower, found.Status)
			}

			// Check Docker native healthcheck if configured
			if strings.Contains(statusLower, "(unhealthy)") {
				return fmt.Errorf("container healthcheck reported unhealthy: %s", found.Status)
			}

			// If state is running and not restarting
			if stateLower == "running" && !strings.HasPrefix(statusLower, "restarting") {
				// If Docker native healthcheck is still starting, wait for it
				if strings.Contains(statusLower, "(health: starting)") {
					time.Sleep(interval)
					continue
				}

				// Stage 2: HTTP Readiness probe if configured
				if cfg.HTTPProbePort > 0 {
					httpPath := cfg.HTTPProbePath
					if httpPath == "" {
						httpPath = "/"
					}
					if !strings.HasPrefix(httpPath, "/") {
						httpPath = "/" + httpPath
					}

					probeURL := fmt.Sprintf("http://127.0.0.1:%d%s", cfg.HTTPProbePort, httpPath)
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
					if err == nil {
						resp, err := rp.httpClient.Do(req)
						if err != nil {
							// Connection refused or probe timeout, wait and retry
							time.Sleep(interval)
							continue
						}
						resp.Body.Close()
						if resp.StatusCode != expectedHTTP {
							time.Sleep(interval)
							continue
						}
					}
				}

				// Stage 3: Readiness Grace Window
				if cfg.ReadinessGraceSec > 0 {
					graceTimer := time.NewTimer(time.Duration(cfg.ReadinessGraceSec) * time.Second)
					select {
					case <-ctx.Done():
						graceTimer.Stop()
						return ctx.Err()
					case <-graceTimer.C:
					}

					// Verify it didn't immediately crash during grace window
					recheck := rp.dockerClient.InspectContainers()
					for _, c := range recheck.Containers {
						if c.ID == found.ID {
							if strings.ToLower(c.State) == "exited" || strings.ToLower(c.State) == "dead" {
								return fmt.Errorf("container crashed during readiness grace period: %s", c.Status)
							}
							break
						}
					}
				}

				// Successfully passed all readiness checks
				return nil
			}
		}

		time.Sleep(interval)
	}
}
