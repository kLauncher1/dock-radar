package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// BatchActionResult captures individual container outcomes during batch executions.
type BatchActionResult struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Action  string `json:"action"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// BatchOperationSummary aggregates multi-container execution results.
type BatchOperationSummary struct {
	Action      string              `json:"action"`
	Total       int                 `json:"total"`
	Succeeded   int                 `json:"succeeded"`
	Failed      int                 `json:"failed"`
	Results     []BatchActionResult `json:"results"`
	CompletedAt time.Time           `json:"completed_at"`
}

// ContainersPruneReport details inactive containers purged and storage space recovered.
type ContainersPruneReport struct {
	ContainersDeleted []string  `json:"containers_deleted"`
	SpaceReclaimed    uint64    `json:"space_reclaimed"`
	CompletedAt       time.Time `json:"completed_at"`
}

type dockerPruneAPIResponse struct {
	ContainersDeleted []string `json:"ContainersDeleted"`
	SpaceReclaimed    uint64   `json:"SpaceReclaimed"`
}

// RestartAll iterates over all active running containers and restarts each.
func (c *Client) RestartAll(ctx context.Context, timeoutSeconds int) (BatchOperationSummary, error) {
	summary := BatchOperationSummary{
		Action:      "restart_all",
		Results:     make([]BatchActionResult, 0),
		CompletedAt: time.Now().UTC(),
	}

	status := c.InspectContainers()
	if !status.Available {
		return summary, fmt.Errorf("%w: %s", ErrDaemonUnreachable, status.Error)
	}

	var targets []ContainerSummary
	for _, ct := range status.Containers {
		if strings.EqualFold(ct.State, "running") {
			targets = append(targets, ct)
		}
	}

	summary.Total = len(targets)
	for _, ct := range targets {
		cName := containerDisplayName(ct)
		res := BatchActionResult{
			ID:     ct.ID,
			Name:   cName,
			Action: "restart",
		}

		err := c.RestartContainer(ctx, ct.ID, timeoutSeconds)
		if err != nil {
			res.Success = false
			res.Error = err.Error()
			summary.Failed++
		} else {
			res.Success = true
			summary.Succeeded++
		}
		summary.Results = append(summary.Results, res)
	}

	summary.CompletedAt = time.Now().UTC()
	return summary, nil
}

// StopAll halts all currently running containers with a graceful timeout.
func (c *Client) StopAll(ctx context.Context, timeoutSeconds int) (BatchOperationSummary, error) {
	summary := BatchOperationSummary{
		Action:      "stop_all",
		Results:     make([]BatchActionResult, 0),
		CompletedAt: time.Now().UTC(),
	}

	status := c.InspectContainers()
	if !status.Available {
		return summary, fmt.Errorf("%w: %s", ErrDaemonUnreachable, status.Error)
	}

	var targets []ContainerSummary
	for _, ct := range status.Containers {
		if strings.EqualFold(ct.State, "running") {
			targets = append(targets, ct)
		}
	}

	summary.Total = len(targets)
	for _, ct := range targets {
		cName := containerDisplayName(ct)
		res := BatchActionResult{
			ID:     ct.ID,
			Name:   cName,
			Action: "stop",
		}

		err := c.StopContainer(ctx, ct.ID, timeoutSeconds)
		if err != nil {
			res.Success = false
			res.Error = err.Error()
			summary.Failed++
		} else {
			res.Success = true
			summary.Succeeded++
		}
		summary.Results = append(summary.Results, res)
	}

	summary.CompletedAt = time.Now().UTC()
	return summary, nil
}

// PruneContainers purges inactive containers via Docker /v1.43/containers/prune with manual fallback.
func (c *Client) PruneContainers(ctx context.Context) (ContainersPruneReport, error) {
	report := ContainersPruneReport{
		ContainersDeleted: make([]string, 0),
		SpaceReclaimed:    0,
		CompletedAt:       time.Now().UTC(),
	}

	// 1. Attempt official prune endpoint
	reqURL := fmt.Sprintf("%s/v1.43/containers/prune", c.BaseURL())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
	if err != nil {
		return report, fmt.Errorf("failed to build prune request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var pruneResp dockerPruneAPIResponse
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
			if err := json.Unmarshal(bodyBytes, &pruneResp); err == nil {
				if pruneResp.ContainersDeleted != nil {
					report.ContainersDeleted = pruneResp.ContainersDeleted
				}
				report.SpaceReclaimed = pruneResp.SpaceReclaimed
				report.CompletedAt = time.Now().UTC()
				return report, nil
			}
		}
	}

	// 2. Fallback: inspect inactive containers (exited, dead, created) and remove manually
	status := c.InspectContainers()
	if !status.Available {
		return report, fmt.Errorf("%w: %s", ErrDaemonUnreachable, status.Error)
	}

	for _, ct := range status.Containers {
		state := strings.ToLower(ct.State)
		if state == "running" || state == "restarting" {
			continue
		}

		delURL := fmt.Sprintf("%s/v1.43/containers/%s?v=1", c.BaseURL(), ct.ID)
		delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, delURL, nil)
		if err != nil {
			continue
		}

		delResp, err := c.httpClient.Do(delReq)
		if err == nil {
			delResp.Body.Close()
			if delResp.StatusCode == http.StatusOK || delResp.StatusCode == http.StatusNoContent || delResp.StatusCode == http.StatusNotFound {
				report.ContainersDeleted = append(report.ContainersDeleted, ct.ID)
			}
		}
	}

	report.CompletedAt = time.Now().UTC()
	return report, nil
}

func containerDisplayName(c ContainerSummary) string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	if len(c.ID) > 12 {
		return c.ID[:12]
	}
	return c.ID
}
