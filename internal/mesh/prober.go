package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ProberConfig defines configuration settings for mesh cluster polling.
type ProberConfig struct {
	Interval   time.Duration
	Timeout    time.Duration
	HTTPClient *http.Client
	Token      string
}

// Prober runs background health checks and telemetry polling against registered nodes.
type Prober struct {
	registry *Registry
	cfg      ProberConfig
	stopCh   chan struct{}
	stopOnce sync.Once
}

type systemProbeResp struct {
	Hostname      string `json:"hostname"`
	NumGoroutine  int    `json:"num_goroutine"`
	AllocMB       uint64 `json:"alloc_mb"`
	SysMB         uint64 `json:"sys_mb"`
	UptimeSeconds uint64 `json:"uptime_seconds"`
}

type dockerContainerSummary struct {
	ID      string   `json:"id"`
	Names   []string `json:"names"`
	Image   string   `json:"image"`
	Status  string   `json:"status"`
	State   string   `json:"state"`
	Created int64    `json:"created"`
	Ports   string   `json:"ports"`
}

type dockerProbeResp struct {
	Available    bool                     `json:"available"`
	TotalCount   int                      `json:"total_count"`
	RunningCount int                      `json:"running_count"`
	Containers   []dockerContainerSummary `json:"containers"`
}

// NewProber initializes a Prober with safe defaults.
func NewProber(registry *Registry, cfg ProberConfig) *Prober {
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout: cfg.Timeout,
		}
	}

	return &Prober{
		registry: registry,
		cfg:      cfg,
		stopCh:   make(chan struct{}),
	}
}

// ProbeNode executes a single health and metrics check against a specified cluster node.
func (p *Prober) ProbeNode(ctx context.Context, n *Node) {
	if n == nil || n.Address == "" {
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()

	start := time.Now()

	// 1. Fetch system metrics
	sysURL := fmt.Sprintf("%s/api/system", n.Address)
	sysReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, sysURL, nil)
	if err != nil {
		p.registry.UpdateNodeStatus(n.ID, NodeStatusOffline, 0, NodeMetrics{}, nil, err.Error())
		return
	}
	if p.cfg.Token != "" {
		sysReq.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	}

	sysResp, err := p.cfg.HTTPClient.Do(sysReq)
	if err != nil {
		p.registry.UpdateNodeStatus(n.ID, NodeStatusOffline, 0, NodeMetrics{}, nil, err.Error())
		return
	}
	defer sysResp.Body.Close()

	if sysResp.StatusCode != http.StatusOK {
		p.registry.UpdateNodeStatus(n.ID, NodeStatusOffline, 0, NodeMetrics{}, nil,
			fmt.Sprintf("HTTP %d from %s", sysResp.StatusCode, sysURL))
		return
	}

	sysBody, err := io.ReadAll(io.LimitReader(sysResp.Body, 1024*1024))
	if err != nil {
		p.registry.UpdateNodeStatus(n.ID, NodeStatusOffline, 0, NodeMetrics{}, nil, err.Error())
		return
	}

	var sysData systemProbeResp
	if err := json.Unmarshal(sysBody, &sysData); err != nil {
		p.registry.UpdateNodeStatus(n.ID, NodeStatusOffline, 0, NodeMetrics{}, nil,
			fmt.Sprintf("failed to parse system JSON: %v", err))
		return
	}

	latencyMs := time.Since(start).Milliseconds()

	// 2. Fetch Docker status
	dockURL := fmt.Sprintf("%s/api/docker", n.Address)
	dockReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, dockURL, nil)
	if err != nil {
		p.registry.UpdateNodeStatus(n.ID, NodeStatusOffline, latencyMs, NodeMetrics{}, nil, err.Error())
		return
	}
	if p.cfg.Token != "" {
		dockReq.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	}

	dockResp, err := p.cfg.HTTPClient.Do(dockReq)
	if err != nil {
		p.registry.UpdateNodeStatus(n.ID, NodeStatusDegraded, latencyMs, NodeMetrics{
			Goroutines:    sysData.NumGoroutine,
			UptimeSeconds: sysData.UptimeSeconds,
		}, nil, fmt.Sprintf("docker probe failed: %v", err))
		return
	}
	defer dockResp.Body.Close()

	var dockData dockerProbeResp
	if dockResp.StatusCode == http.StatusOK {
		dockBody, readErr := io.ReadAll(io.LimitReader(dockResp.Body, 4*1024*1024))
		if readErr == nil {
			_ = json.Unmarshal(dockBody, &dockData)
		}
	}

	// 3. Assemble unified node metrics and container inventory
	nodeMetrics := NodeMetrics{
		MemoryUsedBytes:   sysData.AllocMB * 1024 * 1024,
		MemoryTotalBytes:  sysData.SysMB * 1024 * 1024,
		Goroutines:        sysData.NumGoroutine,
		UptimeSeconds:     sysData.UptimeSeconds,
		ContainersRunning: dockData.RunningCount,
		ContainersTotal:   dockData.TotalCount,
	}
	if sysData.SysMB > 0 {
		nodeMetrics.MemoryPercent = (float64(sysData.AllocMB) / float64(sysData.SysMB)) * 100.0
	}

	containers := make([]RemoteContainer, 0, len(dockData.Containers))
	for _, c := range dockData.Containers {
		containers = append(containers, RemoteContainer{
			ID:       c.ID,
			Names:    c.Names,
			Image:    c.Image,
			Status:   c.Status,
			State:    c.State,
			Created:  c.Created,
			Ports:    c.Ports,
			NodeID:   n.ID,
			NodeName: n.Name,
		})
	}

	status := NodeStatusOnline
	if !dockData.Available {
		status = NodeStatusDegraded
	}

	p.registry.UpdateNodeStatus(n.ID, status, latencyMs, nodeMetrics, containers, "")
}

// ProbeOnce executes concurrent probes across all registered nodes in the mesh.
func (p *Prober) ProbeOnce(ctx context.Context) {
	nodes := p.registry.List()
	if len(nodes) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(node *Node) {
			defer wg.Done()
			p.ProbeNode(ctx, node)
		}(n)
	}
	wg.Wait()
}

// Start initiates the recurring probe ticker until the context is canceled or Stop() is called.
func (p *Prober) Start(ctx context.Context) {
	p.ProbeOnce(ctx)

	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.ProbeOnce(ctx)
		}
	}
}

// Stop cleanly terminates the recurring probe loop.
func (p *Prober) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})
}
