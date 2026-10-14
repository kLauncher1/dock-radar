package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RawMemoryStats represents memory accounting structures returned by Docker daemon.
type RawMemoryStats struct {
	Usage    uint64            `json:"usage"`
	MaxUsage uint64            `json:"max_usage"`
	Limit    uint64            `json:"limit"`
	Stats    map[string]uint64 `json:"stats,omitempty"`
}

// RawCPUUsage represents detailed per-CPU and total cycle counts.
type RawCPUUsage struct {
	TotalUsage        uint64   `json:"total_usage"`
	PercpuUsage       []uint64 `json:"percpu_usage,omitempty"`
	UsageInKernelmode uint64   `json:"usage_in_kernelmode"`
	UsageInUsermode   uint64   `json:"usage_in_usermode"`
}

// RawCPUStats represents system and container CPU accounting metrics.
type RawCPUStats struct {
	CPUUsage       RawCPUUsage `json:"cpu_usage"`
	SystemCPUUsage uint64      `json:"system_cpu_usage"`
	OnlineCPUs     uint32      `json:"online_cpus"`
}

// RawContainerStatsResponse represents the unmarshaled Docker /stats API payload.
type RawContainerStatsResponse struct {
	Read        time.Time      `json:"read"`
	Preread     time.Time      `json:"preread"`
	Name        string         `json:"name"`
	ID          string         `json:"id"`
	MemoryStats RawMemoryStats `json:"memory_stats"`
	CPUStats    RawCPUStats    `json:"cpu_stats"`
	PreCPUStats RawCPUStats    `json:"precpu_stats"`
}

// ContainerStats encapsulates processed resource metrics for a container.
type ContainerStats struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	MemoryUsage   uint64    `json:"memory_usage"`
	MemoryLimit   uint64    `json:"memory_limit"`
	MemoryPercent float64   `json:"memory_percent"`
	CPUPercent    float64   `json:"cpu_percent"`
	Timestamp     time.Time `json:"timestamp"`
}

// CalculateCPUPercent derives normalized CPU utilization percentage across online cores.
func CalculateCPUPercent(cpu, preCPU RawCPUStats) float64 {
	cpuDelta := float64(cpu.CPUUsage.TotalUsage) - float64(preCPU.CPUUsage.TotalUsage)
	systemDelta := float64(cpu.SystemCPUUsage) - float64(preCPU.SystemCPUUsage)

	if systemDelta <= 0.0 || cpuDelta <= 0.0 {
		return 0.0
	}

	onlineCPUs := float64(cpu.OnlineCPUs)
	if onlineCPUs <= 0.0 {
		if len(cpu.CPUUsage.PercpuUsage) > 0 {
			onlineCPUs = float64(len(cpu.CPUUsage.PercpuUsage))
		} else {
			onlineCPUs = 1.0
		}
	}

	percent := (cpuDelta / systemDelta) * onlineCPUs * 100.0
	if percent < 0.0 {
		return 0.0
	}
	return percent
}

// CalculateEffectiveMemory adjusts raw usage by subtracting inactive file cache if available.
func CalculateEffectiveMemory(mem RawMemoryStats) (usage uint64, limit uint64, percent float64) {
	limit = mem.Limit
	rawUsage := mem.Usage

	// In cgroup v1 and v2, cache/inactive_file can be reclaimed by kernel under pressure
	if mem.Stats != nil {
		if inactiveFile, ok := mem.Stats["inactive_file"]; ok && rawUsage > inactiveFile {
			rawUsage -= inactiveFile
		} else if cache, ok := mem.Stats["total_inactive_file"]; ok && rawUsage > cache {
			rawUsage -= cache
		}
	}

	usage = rawUsage
	if limit > 0 {
		percent = (float64(usage) / float64(limit)) * 100.0
		if percent > 100.0 {
			percent = 100.0
		}
	}
	return usage, limit, percent
}

// GetContainerStats queries real-time resource utilization snapshot for a specific container.
func (c *Client) GetContainerStats(ctx context.Context, id string) (*ContainerStats, error) {
	if err := ValidateContainerID(id); err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/v1.43/containers/%s/stats?stream=false", c.BaseURL(), id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create container stats request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var raw RawContainerStatsResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&raw); err != nil {
			return nil, fmt.Errorf("failed to decode stats JSON payload: %w", err)
		}

		cleanName := strings.TrimPrefix(raw.Name, "/")
		if cleanName == "" {
			cleanName = id
		}

		effUsage, effLimit, memPercent := CalculateEffectiveMemory(raw.MemoryStats)
		cpuPercent := CalculateCPUPercent(raw.CPUStats, raw.PreCPUStats)

		ts := raw.Read
		if ts.IsZero() {
			ts = time.Now().UTC()
		}

		return &ContainerStats{
			ID:            id,
			Name:          cleanName,
			MemoryUsage:   effUsage,
			MemoryLimit:   effLimit,
			MemoryPercent: memPercent,
			CPUPercent:    cpuPercent,
			Timestamp:     ts,
		}, nil

	case http.StatusNotFound:
		return nil, ErrContainerNotFound
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("docker stats API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

// InspectAllContainerStats fetches resource telemetry across all running containers concurrently.
func (c *Client) InspectAllContainerStats(ctx context.Context) []ContainerStats {
	daemonStatus := c.InspectContainers()
	if !daemonStatus.Available || len(daemonStatus.Containers) == 0 {
		return nil
	}

	type result struct {
		stats *ContainerStats
		err   error
	}

	var runningIDs []string
	for _, cont := range daemonStatus.Containers {
		if cont.State == "running" {
			runningIDs = append(runningIDs, cont.ID)
		}
	}

	if len(runningIDs) == 0 {
		return nil
	}

	results := make(chan result, len(runningIDs))
	semaphore := make(chan struct{}, 8) // Cap parallel queries to 8 to prevent socket saturation
	var wg sync.WaitGroup

	for _, cid := range runningIDs {
		wg.Add(1)
		go func(containerID string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()

			st, err := c.GetContainerStats(reqCtx, containerID)
			results <- result{stats: st, err: err}
		}(cid)
	}

	wg.Wait()
	close(results)

	var output []ContainerStats
	for res := range results {
		if res.err == nil && res.stats != nil {
			output = append(output, *res.stats)
		}
	}

	return output
}
