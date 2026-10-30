package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/anomaly"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/ebpf"
	"github.com/kLauncher1/dock-radar/internal/federation"
	"github.com/kLauncher1/dock-radar/internal/firewall"
	"github.com/kLauncher1/dock-radar/internal/gitops"
	"github.com/kLauncher1/dock-radar/internal/healing"
	"github.com/kLauncher1/dock-radar/internal/logs"
	"github.com/kLauncher1/dock-radar/internal/mesh"
	"github.com/kLauncher1/dock-radar/internal/raft"
	"github.com/kLauncher1/dock-radar/internal/ratelimit"
	"github.com/kLauncher1/dock-radar/internal/rolling"
	"github.com/kLauncher1/dock-radar/internal/scanner"
	"github.com/kLauncher1/dock-radar/internal/security"
	"github.com/kLauncher1/dock-radar/internal/storage"
	"github.com/kLauncher1/dock-radar/internal/system"
)

// ActionRequest parses input parameters for container control endpoints.
type ActionRequest struct {
	ID      string `json:"id"`
	Timeout int    `json:"timeout,omitempty"`
}

// ActionResponse provides structured results for container control invocations.
type ActionResponse struct {
	Success   bool      `json:"success"`
	Action    string    `json:"action"`
	ID        string    `json:"id"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// HandlerConfig encapsulates services, buffers, and security policies.
type HandlerConfig struct {
	DockerClient     *docker.Client
	RateLimiter      *security.RateLimiter
	LogBuffer        *logs.RingBuffer
	AlertConfigStore *alert.ConfigStore
	AlertDispatcher  *alert.Dispatcher
	AlertMonitor     *alert.Monitor
	AuditLogger      *audit.Logger
	MeshRegistry     *mesh.Registry
	MeshProber       *mesh.Prober
	MeshDiscovery    *mesh.DiscoveryEngine
	MeshGossip       *mesh.GossipEngine
	HealingEngine    *healing.RemediationEngine
	AnomalyDetector  *anomaly.Detector
	RollingEngine    *rolling.Engine
	StorageManager   *storage.Manager
	EBPFEngine       *ebpf.Engine
	FederationEngine *federation.Engine
	ScannerEngine    *scanner.ScannerEngine
	RateLimitEngine  *ratelimit.LimiterEngine
	FirewallEngine   *firewall.Engine
	GitOpsEngine     *gitops.Engine
	RaftEngine       *raft.Engine
	AppVersion       string
	TokenAuth        *security.TokenAuth
	AllowRemote      bool
}

// RegisterRoutes sets up all API endpoints and static file serving on the provided ServeMux.
func RegisterRoutes(mux *http.ServeMux, dockerClient *docker.Client, staticFS fs.FS) *HandlerConfig {
	return RegisterRoutesWithSecurity(mux, dockerClient, staticFS, nil, false)
}

// RegisterRoutesWithSecurity sets up API endpoints with Bearer token authentication and remote access policies.
func RegisterRoutesWithSecurity(mux *http.ServeMux, dockerClient *docker.Client, staticFS fs.FS, tokenAuth *security.TokenAuth, allowRemote bool) *HandlerConfig {
	// Initialize a burst of 5 actions with 1 refill per second
	limiter := security.NewRateLimiter(5.0, 1.0)
	ringBuffer := logs.NewRingBuffer(2000)
	ringBuffer.Append(logs.LogEntry{
		ID:        "system",
		Stream:    "system",
		Timestamp: time.Now().UTC(),
		Message:   "Dock-Radar single-binary engine initialized.",
	})

	alertCfgStore := alert.NewConfigStore(alert.DefaultConfig())
	alertDispatcher := alert.NewDispatcher(alertCfgStore)
	alertMonitor := alert.NewMonitor(dockerClient, alertCfgStore, alertDispatcher)
	auditLogger := audit.NewLogger(2000)
	auditLogger.Log(audit.AuditEvent{
		Action:  "system_init",
		Target:  "dock-radar",
		Details: map[string]any{"version": "1.6.0"},
	})

	healingPolicyStore := healing.NewPolicyStore(healing.DefaultPolicyConfig())
	healingHistory := healing.NewHistoryBuffer(1000)
	healingEngine := healing.NewRemediationEngine(dockerClient, healingPolicyStore, healingHistory, auditLogger)

	anomalyDetector := anomaly.NewDetector(dockerClient, alertDispatcher)
	rollingEngine := rolling.NewEngine(dockerClient, auditLogger, alertDispatcher)
	ebpfEngine := ebpf.NewEngine(ebpf.DefaultEBPFConfig(), dockerClient, alertDispatcher, auditLogger)
	scannerEngine := scanner.NewEngine(scanner.DefaultScannerConfig(), dockerClient, alertDispatcher, auditLogger)
	rateLimitEngine := ratelimit.NewLimiterEngine(ratelimit.DefaultLimiterConfig(), "local-node", alertDispatcher, auditLogger)
	firewallEngine := firewall.NewEngine(firewall.DefaultFirewallConfig(), dockerClient, alertDispatcher, auditLogger)
	gitopsEngine := gitops.NewEngine(gitops.DefaultGitOpsConfig(), dockerClient, alertDispatcher, auditLogger)
	raftEngine, _ := raft.NewEngine(raft.DefaultRaftConfig(), raft.NewStateMachine(), nil, auditLogger, alertDispatcher)

	cfg := &HandlerConfig{
		DockerClient:     dockerClient,
		RateLimiter:      limiter,
		LogBuffer:        ringBuffer,
		AlertConfigStore: alertCfgStore,
		AlertDispatcher:  alertDispatcher,
		AlertMonitor:     alertMonitor,
		AuditLogger:      auditLogger,
		HealingEngine:    healingEngine,
		AnomalyDetector:  anomalyDetector,
		RollingEngine:    rollingEngine,
		EBPFEngine:       ebpfEngine,
		ScannerEngine:    scannerEngine,
		RateLimitEngine:  rateLimitEngine,
		FirewallEngine:   firewallEngine,
		GitOpsEngine:     gitopsEngine,
		RaftEngine:       raftEngine,
		AppVersion:       "2.6.0",
		TokenAuth:        tokenAuth,
		AllowRemote:      allowRemote,
	}

	// Real-time system telemetry
	mux.HandleFunc("/api/system", cfg.handleSystemMetrics)

	// Docker daemon & container inspection
	mux.HandleFunc("/api/docker", cfg.handleDockerStatus)

	// Container lifecycle controls
	mux.HandleFunc("/api/docker/restart", cfg.handleContainerRestart)
	mux.HandleFunc("/api/docker/stop", cfg.handleContainerStop)

	// Docker Compose Topology & Stack Inspector
	mux.HandleFunc("/api/docker/compose", cfg.handleComposeStacks)
	mux.HandleFunc("/api/docker/compose/action", cfg.handleComposeAction)

	// Real-time log streaming & WebSocket feed
	mux.HandleFunc("/api/docker/logs", cfg.handleContainerLogs)

	// Interactive in-browser container shell execution via WebSocket
	mux.HandleFunc("/api/docker/exec", cfg.handleContainerExec)

	// Prometheus metrics exporter endpoint
	mux.HandleFunc("/metrics", cfg.handlePrometheusMetrics)

	// Batch container actions
	mux.HandleFunc("/api/docker/batch", cfg.handleBatchAction)

	// Audit trail export
	mux.HandleFunc("/api/audit/export", cfg.handleAuditExport)

	// Alert configurations & webhook channels
	mux.HandleFunc("/api/alerts/config", cfg.handleAlertConfig)
	mux.HandleFunc("/api/alerts/events", cfg.handleAlertEvents)
	mux.HandleFunc("/api/alerts/test", cfg.handleAlertTest)

	// Autonomous Self-Healing Container Policies & Remediation Engine
	mux.HandleFunc("/api/healing/config", cfg.handleHealingConfig)
	mux.HandleFunc("/api/healing/status", cfg.handleHealingStatus)
	mux.HandleFunc("/api/healing/history", cfg.handleHealingHistory)
	mux.HandleFunc("/api/healing/reset", cfg.handleHealingReset)

	// Predictive Anomaly & OOM Resource Alarms
	mux.HandleFunc("/api/anomaly/predictions", cfg.handleAnomalyPredictions)
	mux.HandleFunc("/api/anomaly/config", cfg.handleAnomalyConfig)
	mux.HandleFunc("/api/anomaly/events", cfg.handleAnomalyEvents)

	// Authentication status and token verification
	mux.HandleFunc("/api/auth/status", cfg.handleAuthStatus)
	mux.HandleFunc("/api/auth/verify", cfg.handleAuthVerify)

	// Multi-Host Agent Mesh & Remote Node Aggregator
	mux.HandleFunc("/api/nodes", cfg.handleMeshNodes)
	mux.HandleFunc("/api/nodes/register", cfg.handleMeshNodes)
	mux.HandleFunc("/api/nodes/heartbeat", cfg.handleNodeHeartbeat)
	mux.HandleFunc("/api/cluster/summary", cfg.handleClusterSummary)
	mux.HandleFunc("/api/cluster/containers", cfg.handleClusterContainers)

	// Dynamic Multi-Node Cluster Mesh & Gossip Protocol Discovery
	mux.HandleFunc("/api/mesh/discovery", cfg.handleMeshDiscovery)
	mux.HandleFunc("/api/mesh/discovery/beacon", cfg.handleMeshDiscovery)
	mux.HandleFunc("/api/mesh/gossip", cfg.handleMeshGossip)

	// Zero-Downtime Rolling Restarts & Traffic Draining
	mux.HandleFunc("/api/rolling/start", cfg.handleRollingStart)
	mux.HandleFunc("/api/rolling/status", cfg.handleRollingStatus)
	mux.HandleFunc("/api/rolling/operations", cfg.handleRollingOperations)
	mux.HandleFunc("/api/rolling/abort", cfg.handleRollingAbort)

	// Distributed Ephemeral Log Storage & S3 Offloader
	mux.HandleFunc("/api/logs/storage/status", cfg.handleStorageStatus)
	mux.HandleFunc("/api/logs/storage/chunks", cfg.handleStorageChunks)
	mux.HandleFunc("/api/logs/storage/chunk", cfg.handleStorageChunk)
	mux.HandleFunc("/api/logs/storage/flush", cfg.handleStorageFlush)
	mux.HandleFunc("/api/logs/storage/config", cfg.handleStorageConfig)
	mux.HandleFunc("/api/logs/storage/test", cfg.handleStorageTest)

	// Adaptive Kernel eBPF Telemetry & Security Engine
	mux.HandleFunc("/api/ebpf/status", cfg.handleEBPFStatus)
	mux.HandleFunc("/api/ebpf/flows", cfg.handleEBPFFlows)
	mux.HandleFunc("/api/ebpf/security/events", cfg.handleEBPFSecurityEvents)
	mux.HandleFunc("/api/ebpf/security/rules", cfg.handleEBPFSecurityRules)
	mux.HandleFunc("/api/ebpf/reset", cfg.handleEBPFReset)
	mux.HandleFunc("/api/ebpf/trigger-test", cfg.handleEBPFTriggerTest)

	// Multi-Region Edge Peer Federation & WAN Sync
	mux.HandleFunc("/api/federation/status", cfg.handleFederationStatus)
	mux.HandleFunc("/api/federation/regions", cfg.handleFederationRegions)
	mux.HandleFunc("/api/federation/sync", cfg.handleFederationSync)
	mux.HandleFunc("/api/federation/routes", cfg.handleFederationRoutes)
	mux.HandleFunc("/api/federation/failover", cfg.handleFederationFailover)
	mux.HandleFunc("/api/federation/config", cfg.handleFederationConfig)

	// Container Image Vulnerability Scanner & SBOM Audit
	mux.HandleFunc("/api/scanner/status", cfg.handleScannerStatus)
	mux.HandleFunc("/api/scanner/reports", cfg.handleScannerReports)
	mux.HandleFunc("/api/scanner/report", cfg.handleScannerReport)
	mux.HandleFunc("/api/scanner/scan", cfg.handleScannerScan)
	mux.HandleFunc("/api/scanner/sbom", cfg.handleScannerSBOM)
	mux.HandleFunc("/api/scanner/gating", cfg.handleScannerGating)

	// Distributed Rate-Limiting & Global Quota Orchestrator
	mux.HandleFunc("/api/ratelimit/status", cfg.handleRateLimitStatus)
	mux.HandleFunc("/api/ratelimit/tenants", cfg.handleRateLimitTenants)
	mux.HandleFunc("/api/ratelimit/bans", cfg.handleRateLimitBans)
	mux.HandleFunc("/api/ratelimit/sync", cfg.handleRateLimitSync)
	mux.HandleFunc("/api/ratelimit/config", cfg.handleRateLimitConfig)

	// eBPF Micro-Firewall & Container Network Isolator
	mux.HandleFunc("/api/firewall/status", cfg.handleFirewallStatus)
	mux.HandleFunc("/api/firewall/rules", cfg.handleFirewallRules)
	mux.HandleFunc("/api/firewall/isolation", cfg.handleFirewallIsolation)
	mux.HandleFunc("/api/firewall/isolate", cfg.handleFirewallIsolate)
	mux.HandleFunc("/api/firewall/unisolate", cfg.handleFirewallUnisolate)
	mux.HandleFunc("/api/firewall/bandwidth", cfg.handleFirewallBandwidth)
	mux.HandleFunc("/api/firewall/ddos/alerts", cfg.handleFirewallDDoSAlerts)
	mux.HandleFunc("/api/firewall/simulate", cfg.handleFirewallSimulate)
	mux.HandleFunc("/api/firewall/config", cfg.handleFirewallConfig)

	// GitOps Continuous Sync & Webhook Auto-Deployer
	mux.HandleFunc("/api/gitops/status", cfg.handleGitOpsStatus)
	mux.HandleFunc("/api/gitops/repos", cfg.handleGitOpsRepos)
	mux.HandleFunc("/api/gitops/sync", cfg.handleGitOpsSync)
	mux.HandleFunc("/api/gitops/deploy", cfg.handleGitOpsDeploy)
	mux.HandleFunc("/api/gitops/rollback", cfg.handleGitOpsRollback)
	mux.HandleFunc("/api/gitops/deployments", cfg.handleGitOpsDeployments)
	mux.HandleFunc("/api/gitops/webhook", cfg.handleGitOpsWebhook)
	mux.HandleFunc("/api/gitops/config", cfg.handleGitOpsConfig)

	// High-Availability Raft Cluster Consensus Engine
	mux.HandleFunc("/api/raft/status", cfg.handleRaftStatus)
	mux.HandleFunc("/api/raft/fsm", cfg.handleRaftFSM)
	mux.HandleFunc("/api/raft/propose", cfg.handleRaftPropose)
	mux.HandleFunc("/api/raft/peers", cfg.handleRaftPeers)
	mux.HandleFunc("/api/raft/stepdown", cfg.handleRaftStepDown)
	mux.HandleFunc("/api/raft/snapshot", cfg.handleRaftSnapshot)
	mux.HandleFunc("/api/raft/rpc/vote", cfg.handleRaftRPCVote)
	mux.HandleFunc("/api/raft/rpc/append", cfg.handleRaftRPCAppend)

	// Embedded Static UI
	if staticFS != nil {
		mux.Handle("/", http.FileServer(http.FS(staticFS)))
	}

	return cfg
}

func (h *HandlerConfig) authorize(w http.ResponseWriter, r *http.Request, required security.Role) bool {
	if h.TokenAuth != nil && h.TokenAuth.IsEnabled() {
		_, err := h.TokenAuth.Authorize(r, required)
		if err != nil {
			if errors.Is(err, security.ErrUnauthorized) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="dock-radar"`)
				http.Error(w, err.Error(), http.StatusUnauthorized)
			} else {
				http.Error(w, err.Error(), http.StatusForbidden)
			}
			return false
		}
		return true
	}

	if required == security.RoleAdmin {
		if err := security.ValidateLoopbackOrigin(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return false
		}
	}
	return true
}

func (h *HandlerConfig) handleSystemMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	metrics := system.CollectTelemetry()
	_ = json.NewEncoder(w).Encode(metrics)
}

func (h *HandlerConfig) handleDockerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	status := h.DockerClient.InspectContainers()
	_ = json.NewEncoder(w).Encode(status)
}

func (h *HandlerConfig) handleContainerRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if !h.RateLimiter.Allow() {
		w.Header().Set("Retry-After", "2")
		http.Error(w, security.ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
		return
	}

	req, err := parseActionRequest(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid request payload: %v", err), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 10
	}
	if timeout > 300 {
		timeout = 300
	}

	err = h.DockerClient.RestartContainer(ctx, req.ID, timeout)
	if err != nil {
		handleLifecycleError(w, "restart", req.ID, err)
		return
	}

	writeJSONResponse(w, http.StatusOK, ActionResponse{
		Success:   true,
		Action:    "restart",
		ID:        req.ID,
		Message:   fmt.Sprintf("container %s successfully restarted", req.ID),
		Timestamp: time.Now().UTC(),
	})
}

func (h *HandlerConfig) handleContainerStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if !h.RateLimiter.Allow() {
		w.Header().Set("Retry-After", "2")
		http.Error(w, security.ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
		return
	}

	req, err := parseActionRequest(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid request payload: %v", err), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 10
	}
	if timeout > 300 {
		timeout = 300
	}

	err = h.DockerClient.StopContainer(ctx, req.ID, timeout)
	if err != nil {
		handleLifecycleError(w, "stop", req.ID, err)
		return
	}

	writeJSONResponse(w, http.StatusOK, ActionResponse{
		Success:   true,
		Action:    "stop",
		ID:        req.ID,
		Message:   fmt.Sprintf("container %s successfully stopped", req.ID),
		Timestamp: time.Now().UTC(),
	})
}

func parseActionRequest(r *http.Request) (ActionRequest, error) {
	var req ActionRequest

	// Priority 1: JSON body
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err == nil && len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				return req, err
			}
		}
	}

	// Priority 2: Query param fallback
	if req.ID == "" {
		req.ID = r.URL.Query().Get("id")
	}

	if err := docker.ValidateContainerID(req.ID); err != nil {
		return req, err
	}

	return req, nil
}

func handleLifecycleError(w http.ResponseWriter, action, id string, err error) {
	statusCode := http.StatusInternalServerError
	if errors.Is(err, docker.ErrContainerNotFound) {
		statusCode = http.StatusNotFound
	} else if errors.Is(err, docker.ErrInvalidContainerID) {
		statusCode = http.StatusBadRequest
	} else if errors.Is(err, docker.ErrDaemonUnreachable) {
		statusCode = http.StatusBadGateway
	}

	writeJSONResponse(w, statusCode, ActionResponse{
		Success:   false,
		Action:    action,
		ID:        id,
		Message:   err.Error(),
		Timestamp: time.Now().UTC(),
	})
}

func writeJSONResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}



