package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
)

// Engine is the master orchestrator for multi-region edge federation and WAN delta sync.
type Engine struct {
	mu           sync.RWMutex
	config       FederationConfig
	regions      map[string]*Region
	cipher       *TunnelCipher
	tunnels      *TunnelManager
	syncEngine   *DeltaSyncEngine
	router       *GeoRouter
	dockerClient *docker.Client
	auditLogger  *audit.Logger
	alertDisp    *alert.Dispatcher
	httpClient   *http.Client
}

// NewEngine creates and initializes a multi-region edge federation engine.
func NewEngine(cfg FederationConfig, dockerClient *docker.Client, auditLogger *audit.Logger, alertDisp *alert.Dispatcher) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid federation config: %w", err)
	}

	cipher, err := NewTunnelCipher(cfg.TunnelKey, int64(cfg.ProbeTimeoutSec*4))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tunnel cipher: %w", err)
	}

	tm := NewTunnelManager(cfg.LocalRegionID, cipher)
	syncEng := NewDeltaSyncEngine(cfg.LocalRegionID)
	geoRouter := NewGeoRouter()

	engine := &Engine{
		config:       cfg,
		regions:      make(map[string]*Region),
		cipher:       cipher,
		tunnels:      tm,
		syncEngine:   syncEng,
		router:       geoRouter,
		dockerClient: dockerClient,
		auditLogger:  auditLogger,
		alertDisp:    alertDisp,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.ProbeTimeoutSec) * time.Second,
		},
	}

	// Register local region
	engine.regions[cfg.LocalRegionID] = &Region{
		ID:        cfg.LocalRegionID,
		Name:      cfg.LocalRegionName,
		Endpoint:  "http://localhost:9080",
		Status:    RegionStatusOnline,
		PingRTTMs: 0,
	}

	return engine, nil
}

// Start begins background WAN health probing, delta synchronization, and failover monitoring.
func (e *Engine) Start(ctx context.Context) {
	e.mu.RLock()
	interval := time.Duration(e.config.SyncIntervalSec) * time.Second
	e.mu.RUnlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial immediate refresh
	_ = e.SyncNow(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = e.SyncNow(ctx)
		}
	}
}

// SyncNow executes an on-demand probe and delta sync cycle across all edge regions.
func (e *Engine) SyncNow(ctx context.Context) error {
	e.refreshLocalContainers()

	e.mu.Lock()
	regionsToProbe := make([]*Region, 0, len(e.regions))
	for _, reg := range e.regions {
		if reg.ID != e.config.LocalRegionID {
			regionsToProbe = append(regionsToProbe, reg)
		}
	}
	autoFailover := e.config.AutoFailoverEnabled
	maxRetries := e.config.MaxFailoverRetries
	e.mu.Unlock()

	// Probe each remote region concurrently or sequentially
	for _, reg := range regionsToProbe {
		e.probeAndSyncRegion(ctx, reg)
	}

	// Evaluate failover rules
	e.mu.RLock()
	regionsCopy := make(map[string]*Region, len(e.regions))
	for id, r := range e.regions {
		copied := *r
		regionsCopy[id] = &copied
	}
	e.mu.RUnlock()

	events := e.router.EvaluateFailovers(regionsCopy, autoFailover, maxRetries)
	for _, ev := range events {
		if e.auditLogger != nil {
			e.auditLogger.Log(audit.AuditEvent{
				Action: "federation_failover",
				Target: ev.TargetID,
				Details: map[string]any{
					"from_region":  ev.FromRegion,
					"to_region":    ev.ToRegion,
					"reason":       ev.Reason,
					"service_name": ev.ServiceName,
				},
			})
		}
		if e.alertDisp != nil {
			_ = e.alertDisp.Dispatch(ctx, alert.Event{
				Level:     alert.LevelWarning,
				Source:    "federation",
				EventType: "failover",
				Message:   fmt.Sprintf("Traffic failover: %s routed from %s to %s (%s)", ev.ServiceName, ev.FromRegion, ev.ToRegion, ev.Reason),
				Details: map[string]any{
					"target_id":   ev.TargetID,
					"from_region": ev.FromRegion,
					"to_region":   ev.ToRegion,
					"reason":      ev.Reason,
				},
			})
		}
	}

	return nil
}

func (e *Engine) refreshLocalContainers() {
	if e.dockerClient == nil {
		return
	}
	daemonStatus := e.dockerClient.InspectContainers()
	summaries := daemonStatus.Containers

	fedList := make([]FederatedContainer, 0, len(summaries))
	for _, s := range summaries {
		name := ""
		if len(s.Names) > 0 {
			name = s.Names[0]
		}
		fedList = append(fedList, FederatedContainer{
			ID:        s.ID,
			Name:      name,
			Image:     s.Image,
			State:     s.State,
			Status:    s.Status,
			RegionID:  e.config.LocalRegionID,
			UpdatedAt: time.Now().UTC(),
		})
	}
	e.syncEngine.SetLocalContainers(fedList)

	e.mu.Lock()
	if localReg, ok := e.regions[e.config.LocalRegionID]; ok {
		localReg.ContainerCount = len(fedList)
		localReg.LastSyncTime = time.Now().UTC()
	}
	e.mu.Unlock()
}

func (e *Engine) probeAndSyncRegion(ctx context.Context, reg *Region) {
	start := time.Now()
	deltaPayload, err := e.syncEngine.ComputeDelta(reg.ID, "")
	if err != nil {
		e.markRegionFailure(reg, err)
		return
	}

	// Encrypt packet with overlay tunnel cipher
	packet, err := e.tunnels.WrapPayload(reg.ID, deltaPayload)
	if err != nil {
		e.markRegionFailure(reg, err)
		return
	}

	packetBytes, err := json.Marshal(packet)
	if err != nil {
		e.markRegionFailure(reg, err)
		return
	}

	reqURL := fmt.Sprintf("%s/api/federation/sync", reg.Endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(packetBytes))
	if err != nil {
		e.markRegionFailure(reg, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	duration := time.Since(start)

	if err != nil {
		e.markRegionFailure(reg, err)
		e.tunnels.RecordStats(reg.ID, duration.Milliseconds(), int64(len(packetBytes)), 0, false)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var respPacket EncryptedPacket
		if err := json.NewDecoder(resp.Body).Decode(&respPacket); err == nil {
			var remoteDelta DeltaSyncPayload
			if err := e.tunnels.UnwrapPayload(&respPacket, &remoteDelta); err == nil {
				_, _, _, _ = e.syncEngine.ApplyDelta(&remoteDelta)
			}
		}

		e.mu.Lock()
		reg.Status = RegionStatusOnline
		reg.PingRTTMs = duration.Milliseconds()
		reg.ConsecutiveFailures = 0
		reg.LastSyncTime = time.Now().UTC()
		reg.ContainerCount = len(e.syncEngine.GetRegionContainers(reg.ID))
		e.mu.Unlock()

		e.tunnels.RecordStats(reg.ID, duration.Milliseconds(), int64(len(packetBytes)), 128, true)
	} else {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		e.markRegionFailure(reg, fmt.Errorf("status %d: %s", resp.StatusCode, string(body)))
		e.tunnels.RecordStats(reg.ID, duration.Milliseconds(), int64(len(packetBytes)), 0, false)
	}
}

func (e *Engine) markRegionFailure(reg *Region, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	reg.ConsecutiveFailures++
	if reg.ConsecutiveFailures >= e.config.MaxFailoverRetries {
		reg.Status = RegionStatusOffline
	} else {
		reg.Status = RegionStatusDegraded
	}
}

// IngestSyncPayload decrypts an incoming overlay tunnel packet, applies delta, and returns local delta.
func (e *Engine) IngestSyncPayload(packet *EncryptedPacket) (*EncryptedPacket, error) {
	if packet == nil {
		return nil, errors.New("nil sync packet")
	}

	var incomingDelta DeltaSyncPayload
	if err := e.tunnels.UnwrapPayload(packet, &incomingDelta); err != nil {
		return nil, fmt.Errorf("tunnel unwrap error: %w", err)
	}

	_, _, _, err := e.syncEngine.ApplyDelta(&incomingDelta)
	if err != nil {
		return nil, fmt.Errorf("apply delta error: %w", err)
	}

	// Update or register sender region
	e.mu.Lock()
	if senderReg, exists := e.regions[incomingDelta.SenderRegion]; exists {
		senderReg.Status = RegionStatusOnline
		senderReg.LastSyncTime = time.Now().UTC()
		senderReg.ConsecutiveFailures = 0
		senderReg.ContainerCount = len(e.syncEngine.GetRegionContainers(incomingDelta.SenderRegion))
	}
	e.mu.Unlock()

	// Respond with local delta
	responseDelta, err := e.syncEngine.ComputeDelta(incomingDelta.SenderRegion, incomingDelta.Digest.DigestHex)
	if err != nil {
		return nil, fmt.Errorf("compute response delta error: %w", err)
	}

	return e.tunnels.WrapPayload(incomingDelta.SenderRegion, responseDelta)
}

// RegisterRegion registers a new remote edge region into the mesh federation.
func (e *Engine) RegisterRegion(reg *Region) error {
	if reg == nil {
		return errors.New("nil region")
	}
	if err := reg.Validate(); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	reg.Status = RegionStatusOnline
	e.regions[reg.ID] = reg
	e.tunnels.RegisterTunnel(reg.ID, reg.Endpoint)

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action: "federation_region_add",
			Target: reg.ID,
			Details: map[string]any{
				"name":     reg.Name,
				"endpoint": reg.Endpoint,
			},
		})
	}
	return nil
}

// UnregisterRegion removes a region from federation mesh.
func (e *Engine) UnregisterRegion(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if id == e.config.LocalRegionID {
		return errors.New("cannot unregister local region")
	}
	if _, exists := e.regions[id]; !exists {
		return fmt.Errorf("region %q not found", id)
	}

	delete(e.regions, id)
	e.tunnels.UnregisterTunnel(id)

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action: "federation_region_remove",
			Target: id,
		})
	}
	return nil
}

// GetStatus compiles overall federation health and KPI metrics.
func (e *Engine) GetStatus() FederationStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	totalBytes, savedBytes, eff, lastSync := e.syncEngine.Telemetry()
	regList := make([]Region, 0, len(e.regions))
	healthyCount := 0

	for _, reg := range e.regions {
		regList = append(regList, *reg)
		if reg.Status == RegionStatusOnline {
			healthyCount++
		}
	}

	overallStatus := RegionStatusOnline
	if healthyCount == 0 {
		overallStatus = RegionStatusOffline
	} else if healthyCount < len(e.regions) {
		overallStatus = RegionStatusDegraded
	}

	return FederationStatus{
		Enabled:                e.config.Enabled,
		LocalRegionID:          e.config.LocalRegionID,
		LocalRegionName:        e.config.LocalRegionName,
		TotalRegions:           len(e.regions),
		HealthyRegions:         healthyCount,
		ActiveTunnels:          e.tunnels.ActiveCount(),
		TotalSyncBytes:         totalBytes,
		TotalSavedBytes:        savedBytes,
		DeltaEfficiencyPercent: eff,
		FailoverCount:          e.router.FailoverEventsCount(),
		LastSyncTime:           lastSync,
		Regions:                regList,
		Status:                 overallStatus,
	}
}

// Router returns the geo router instance.
func (e *Engine) Router() *GeoRouter {
	return e.router
}

// SyncEngine returns the delta sync engine.
func (e *Engine) SyncEngine() *DeltaSyncEngine {
	return e.syncEngine
}

// TunnelManager returns the overlay tunnel manager.
func (e *Engine) TunnelManager() *TunnelManager {
	return e.tunnels
}

// GetConfig returns a copy of the federation configuration.
func (e *Engine) GetConfig() FederationConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

// UpdateConfig updates runtime configuration parameters.
func (e *Engine) UpdateConfig(cfg FederationConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if cfg.TunnelKey == "" {
		cfg.TunnelKey = e.config.TunnelKey
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	e.config = cfg
	return nil
}
