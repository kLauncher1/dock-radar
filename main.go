package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/api"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/ebpf"
	"github.com/kLauncher1/dock-radar/internal/federation"
	"github.com/kLauncher1/dock-radar/internal/gitops"
	"github.com/kLauncher1/dock-radar/internal/mesh"
	"github.com/kLauncher1/dock-radar/internal/raft"
	"github.com/kLauncher1/dock-radar/internal/scanner"
	"github.com/kLauncher1/dock-radar/internal/security"
	"github.com/kLauncher1/dock-radar/internal/storage"
)

//go:embed web/dist/*
var embeddedWeb embed.FS

const AppVersion = "2.6.0"

func main() {
	portFlag := flag.String("port", "", "Server listening port (env: PORT, default: 9080)")
	tlsFlag := flag.Bool("tls", false, "Enable TLS encryption with auto-generated or custom certs (env: DOCK_RADAR_TLS)")
	tlsCertFlag := flag.String("tls-cert", "", "Path to custom TLS certificate PEM (env: DOCK_RADAR_TLS_CERT)")
	tlsKeyFlag := flag.String("tls-key", "", "Path to custom TLS private key PEM (env: DOCK_RADAR_TLS_KEY)")
	adminTokenFlag := flag.String("admin-token", "", "Bearer token for administrative control (env: DOCK_RADAR_ADMIN_TOKEN or DOCK_RADAR_AUTH_TOKEN)")
	viewerTokenFlag := flag.String("viewer-token", "", "Bearer token for read-only telemetry access (env: DOCK_RADAR_VIEWER_TOKEN)")
	allowRemoteFlag := flag.Bool("allow-remote", false, "Permit remote clients without loopback origin check (env: DOCK_RADAR_ALLOW_REMOTE)")
	nodesFlag := flag.String("nodes", "", "Comma-separated list of remote dock-radar nodes to aggregate (env: DOCK_RADAR_NODES)")
	nodeNameFlag := flag.String("node-name", "", "Human-readable name for this node (env: DOCK_RADAR_NODE_NAME)")
	meshDiscoveryFlag := flag.Bool("mesh-discovery", true, "Enable LAN UDP peer auto-discovery (env: DOCK_RADAR_MESH_DISCOVERY)")
	meshPortFlag := flag.Int("mesh-port", 9085, "UDP port for LAN peer auto-discovery (env: DOCK_RADAR_MESH_PORT)")
	gossipIntervalFlag := flag.Duration("gossip-interval", 2*time.Second, "SWIM gossip failure detection interval (env: DOCK_RADAR_GOSSIP_INTERVAL)")
	s3EndpointFlag := flag.String("s3-endpoint", "", "S3-compatible endpoint URL (env: DOCK_RADAR_S3_ENDPOINT)")
	s3BucketFlag := flag.String("s3-bucket", "", "S3 target bucket name for log archiving (env: DOCK_RADAR_S3_BUCKET)")
	s3RegionFlag := flag.String("s3-region", "us-east-1", "S3 region (env: DOCK_RADAR_S3_REGION, default: us-east-1)")
	s3AccessKeyFlag := flag.String("s3-access-key", "", "S3 access key ID (env: DOCK_RADAR_S3_ACCESS_KEY)")
	s3SecretKeyFlag := flag.String("s3-secret-key", "", "S3 secret access key (env: DOCK_RADAR_S3_SECRET_KEY)")
	s3PrefixFlag := flag.String("s3-prefix", "dock-radar/logs", "S3 object key prefix (env: DOCK_RADAR_S3_PREFIX, default: dock-radar/logs)")
	logStorageDirFlag := flag.String("log-storage-dir", filepath.Join("data", "logs"), "Local ephemeral log chunk storage directory (env: DOCK_RADAR_LOG_STORAGE_DIR)")
	ebpfEnabledFlag := flag.Bool("ebpf", true, "Enable kernel eBPF & socket telemetry engine (env: DOCK_RADAR_EBPF_ENABLED)")
	ebpfModeFlag := flag.String("ebpf-mode", "", "Probe mode override (ebpf_native, procfs_socket, synthetic_trace; env: DOCK_RADAR_EBPF_MODE)")
	ebpfIntervalFlag := flag.Duration("ebpf-interval", 2*time.Second, "eBPF socket sampling interval (env: DOCK_RADAR_EBPF_INTERVAL)")
	federationFlag := flag.Bool("federation", true, "Enable multi-region edge peer federation (env: DOCK_RADAR_FEDERATION_ENABLED)")
	federationRegionFlag := flag.String("federation-region", "us-east-1", "Local edge region identifier (env: DOCK_RADAR_FEDERATION_REGION)")
	federationNameFlag := flag.String("federation-name", "US East (N. Virginia)", "Local edge region friendly name (env: DOCK_RADAR_FEDERATION_NAME)")
	federationKeyFlag := flag.String("federation-key", "dock-radar-federation-default-key-32b", "Shared key for encrypted overlay tunnels (env: DOCK_RADAR_FEDERATION_KEY)")
	wanSyncIntervalFlag := flag.Duration("wan-sync-interval", 30*time.Second, "WAN delta sync interval (env: DOCK_RADAR_WAN_SYNC_INTERVAL)")
	scannerFlag := flag.Bool("scanner", true, "Enable container image vulnerability scanner & SBOM engine (env: DOCK_RADAR_SCANNER_ENABLED)")
	scannerAutoScanFlag := flag.Bool("scanner-auto-scan", true, "Automatically scan images of active containers (env: DOCK_RADAR_SCANNER_AUTO_SCAN)")
	scannerIntervalFlag := flag.Duration("scanner-interval", 60*time.Second, "Vulnerability scan interval (env: DOCK_RADAR_SCANNER_INTERVAL)")
	scannerGatingFlag := flag.String("scanner-gating-severity", "CRITICAL", "Failure severity threshold for deployment gating (env: DOCK_RADAR_SCANNER_GATING_SEVERITY)")
	ratelimitFlag := flag.Bool("ratelimit", true, "Enable distributed rate-limiting & quota orchestrator (env: DOCK_RADAR_RATELIMIT_ENABLED)")
	ratelimitRPSFlag := flag.Float64("ratelimit-default-rps", 50.0, "Default requests per second limit (env: DOCK_RADAR_RATELIMIT_DEFAULT_RPS)")
	ratelimitBurstFlag := flag.Int("ratelimit-burst", 100, "Default token bucket burst capacity (env: DOCK_RADAR_RATELIMIT_BURST)")
	ratelimitAutoBanFlag := flag.Bool("ratelimit-autoban", true, "Automatically ban IPs exceeding abuse thresholds (env: DOCK_RADAR_RATELIMIT_AUTOBAN)")
	ratelimitSecretFlag := flag.String("ratelimit-sync-secret", "", "Shared HMAC secret for cluster rate limit mesh sync (env: DOCK_RADAR_RATELIMIT_SYNC_SECRET)")
	firewallFlag := flag.Bool("firewall", true, "Enable eBPF micro-firewall & container network isolator (env: DOCK_RADAR_FIREWALL_ENABLED)")
	firewallZeroTrustFlag := flag.Bool("firewall-zerotrust", false, "Enable zero-trust network isolation policy by default (env: DOCK_RADAR_FIREWALL_ZEROTRUST)")
	firewallDDoSPPSFlag := flag.Uint64("firewall-ddos-pps", 50000, "Packets/sec threshold for DDoS attack mitigation (env: DOCK_RADAR_FIREWALL_DDOS_PPS)")
	firewallDDoSBPSFlag := flag.Uint64("firewall-ddos-bps", 104857600, "Bytes/sec threshold for DDoS bandwidth exhaustion (env: DOCK_RADAR_FIREWALL_DDOS_BPS)")
	firewallAutoBanFlag := flag.Bool("firewall-autoban", true, "Automatically quarantine containers on severe DDoS attacks (env: DOCK_RADAR_FIREWALL_AUTOBAN)")
	gitopsFlag := flag.Bool("gitops", true, "Enable GitOps continuous sync & webhook auto-deployer (env: DOCK_RADAR_GITOPS_ENABLED)")
	gitopsPollIntervalFlag := flag.Duration("gitops-poll-interval", 30*time.Second, "Default background repository polling interval (env: DOCK_RADAR_GITOPS_POLL_INTERVAL)")
	gitopsStrictSigFlag := flag.Bool("gitops-strict-signatures", false, "Reject commits with missing or invalid cryptographic signatures (env: DOCK_RADAR_GITOPS_STRICT_SIGNATURES)")
	gitopsAutoRollbackFlag := flag.Bool("gitops-auto-rollback", true, "Automatically rollback deployments failing post-deploy health check (env: DOCK_RADAR_GITOPS_AUTO_ROLLBACK)")
	gitopsWebhookSecretFlag := flag.String("gitops-webhook-secret", "", "Default HMAC secret for incoming Git webhooks (env: DOCK_RADAR_GITOPS_WEBHOOK_SECRET)")
	raftFlag := flag.Bool("raft", true, "Enable High-Availability Raft cluster consensus engine (env: DOCK_RADAR_RAFT_ENABLED)")
	raftPeersFlag := flag.String("raft-peers", "", "Comma-separated list of remote Raft consensus peer URLs (env: DOCK_RADAR_RAFT_PEERS)")
	raftHeartbeatFlag := flag.Duration("raft-heartbeat", 200*time.Millisecond, "Raft leader heartbeat interval (env: DOCK_RADAR_RAFT_HEARTBEAT)")
	raftElectionTimeoutFlag := flag.Duration("raft-election-timeout", 1000*time.Millisecond, "Raft election timeout base (env: DOCK_RADAR_RAFT_ELECTION_TIMEOUT)")
	raftDataDirFlag := flag.String("raft-data-dir", filepath.Join("data", "raft"), "Local Raft state directory (env: DOCK_RADAR_RAFT_DATA_DIR)")
	versionFlag := flag.Bool("version", false, "Print dock-radar version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("dock-radar v%s\n", AppVersion)
		return
	}

	port := *portFlag
	if port == "" {
		port = os.Getenv("PORT")
	}
	if port == "" {
		port = "9080"
	}

	useTLS := *tlsFlag || strings.EqualFold(os.Getenv("DOCK_RADAR_TLS"), "true")
	tlsCertPath := *tlsCertFlag
	if tlsCertPath == "" {
		tlsCertPath = os.Getenv("DOCK_RADAR_TLS_CERT")
	}
	tlsKeyPath := *tlsKeyFlag
	if tlsKeyPath == "" {
		tlsKeyPath = os.Getenv("DOCK_RADAR_TLS_KEY")
	}

	adminToken := *adminTokenFlag
	if adminToken == "" {
		adminToken = os.Getenv("DOCK_RADAR_ADMIN_TOKEN")
		if adminToken == "" {
			adminToken = os.Getenv("DOCK_RADAR_AUTH_TOKEN")
		}
	}

	viewerToken := *viewerTokenFlag
	if viewerToken == "" {
		viewerToken = os.Getenv("DOCK_RADAR_VIEWER_TOKEN")
	}

	allowRemote := *allowRemoteFlag || strings.EqualFold(os.Getenv("DOCK_RADAR_ALLOW_REMOTE"), "true")

	nodesStr := *nodesFlag
	if nodesStr == "" {
		nodesStr = os.Getenv("DOCK_RADAR_NODES")
	}

	nodeName := *nodeNameFlag
	if nodeName == "" {
		nodeName = os.Getenv("DOCK_RADAR_NODE_NAME")
	}
	if nodeName == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			nodeName = h
		} else {
			nodeName = "coordinator"
		}
	}

	dockerClient := docker.NewClient()

	subFS, err := fs.Sub(embeddedWeb, "web/dist")
	if err != nil {
		log.Fatalf("Failed to initialize embedded web filesystem: %v", err)
	}

	tokenAuth := security.NewTokenAuth(adminToken, viewerToken, allowRemote)

	s3Endpoint := *s3EndpointFlag
	if s3Endpoint == "" {
		s3Endpoint = os.Getenv("DOCK_RADAR_S3_ENDPOINT")
	}
	s3Bucket := *s3BucketFlag
	if s3Bucket == "" {
		s3Bucket = os.Getenv("DOCK_RADAR_S3_BUCKET")
	}
	s3Region := *s3RegionFlag
	if envRegion := os.Getenv("DOCK_RADAR_S3_REGION"); envRegion != "" {
		s3Region = envRegion
	}
	s3AccessKey := *s3AccessKeyFlag
	if s3AccessKey == "" {
		s3AccessKey = os.Getenv("DOCK_RADAR_S3_ACCESS_KEY")
	}
	s3SecretKey := *s3SecretKeyFlag
	if s3SecretKey == "" {
		s3SecretKey = os.Getenv("DOCK_RADAR_S3_SECRET_KEY")
	}
	s3Prefix := *s3PrefixFlag
	if envPrefix := os.Getenv("DOCK_RADAR_S3_PREFIX"); envPrefix != "" {
		s3Prefix = envPrefix
	}
	logStorageDir := *logStorageDirFlag
	if envStorageDir := os.Getenv("DOCK_RADAR_LOG_STORAGE_DIR"); envStorageDir != "" {
		logStorageDir = envStorageDir
	}

	s3Cfg := storage.S3Config{
		Endpoint:       s3Endpoint,
		Region:         s3Region,
		Bucket:         s3Bucket,
		Prefix:         s3Prefix,
		AccessKey:      s3AccessKey,
		SecretKey:      s3SecretKey,
		StorageClass:   "STANDARD",
		ForcePathStyle: true,
	}
	retCfg := storage.DefaultRetentionConfig()

	storageMgr, err := storage.NewManager(logStorageDir, s3Cfg, retCfg)
	if err != nil {
		log.Printf("Warning: failed to initialize log storage manager: %v", err)
	}

	mux := http.NewServeMux()
	handlerCfg := api.RegisterRoutesWithSecurity(mux, dockerClient, subFS, tokenAuth, allowRemote)
	if handlerCfg != nil {
		handlerCfg.AppVersion = AppVersion
		if storageMgr != nil {
			handlerCfg.StorageManager = storageMgr
		}
	}

	// Launch background log storage and retention loop
	if storageMgr != nil {
		storageCtx, storageCancel := context.WithCancel(context.Background())
		defer storageCancel()
		storageMgr.Start(storageCtx)
	}

	// Launch background alert monitoring loop (10s interval)
	if handlerCfg != nil && handlerCfg.AlertMonitor != nil {
		monitorCtx, monitorCancel := context.WithCancel(context.Background())
		defer monitorCancel()
		go handlerCfg.AlertMonitor.Start(monitorCtx, 10*time.Second)
	}

	// Launch autonomous self-healing remediation loop (5s interval)
	if handlerCfg != nil && handlerCfg.HealingEngine != nil {
		healingCtx, healingCancel := context.WithCancel(context.Background())
		defer healingCancel()
		go handlerCfg.HealingEngine.Start(healingCtx, 5*time.Second)
	}

	// Launch predictive anomaly & OOM trend detection loop (5s interval)
	if handlerCfg != nil && handlerCfg.AnomalyDetector != nil {
		anomalyCtx, anomalyCancel := context.WithCancel(context.Background())
		defer anomalyCancel()
		go handlerCfg.AnomalyDetector.Start(anomalyCtx, 5*time.Second)
	}

	// Launch adaptive kernel eBPF & socket telemetry loop
	if handlerCfg != nil && handlerCfg.EBPFEngine != nil {
		ebpfEnabled := *ebpfEnabledFlag
		if envEnabled := os.Getenv("DOCK_RADAR_EBPF_ENABLED"); envEnabled != "" {
			ebpfEnabled = strings.EqualFold(envEnabled, "true") || envEnabled == "1"
		}
		ebpfMode := *ebpfModeFlag
		if envMode := os.Getenv("DOCK_RADAR_EBPF_MODE"); envMode != "" {
			ebpfMode = envMode
		}
		ebpfInterval := *ebpfIntervalFlag
		if envInterval := os.Getenv("DOCK_RADAR_EBPF_INTERVAL"); envInterval != "" {
			if d, err := time.ParseDuration(envInterval); err == nil && d > 0 {
				ebpfInterval = d
			}
		}

		curCfg := handlerCfg.EBPFEngine.GetConfig()
		curCfg.Enabled = ebpfEnabled
		if ebpfMode != "" {
			curCfg.Mode = ebpf.ProbeMode(ebpfMode)
		}
		if ebpfInterval.Seconds() >= 1 {
			curCfg.SamplingIntervalSec = int(ebpfInterval.Seconds())
		}
		_ = handlerCfg.EBPFEngine.UpdateConfig(curCfg)

		if ebpfEnabled {
			ebpfCtx, ebpfCancel := context.WithCancel(context.Background())
			defer ebpfCancel()
			go handlerCfg.EBPFEngine.Start(ebpfCtx)
		}
	}

	// Launch multi-region edge peer federation and WAN delta sync engine
	enableFederation := *federationFlag
	if envFed := os.Getenv("DOCK_RADAR_FEDERATION_ENABLED"); envFed != "" {
		enableFederation = strings.EqualFold(envFed, "true") || envFed == "1"
	}
	fedRegion := *federationRegionFlag
	if envRegion := os.Getenv("DOCK_RADAR_FEDERATION_REGION"); envRegion != "" {
		fedRegion = envRegion
	}
	fedName := *federationNameFlag
	if envName := os.Getenv("DOCK_RADAR_FEDERATION_NAME"); envName != "" {
		fedName = envName
	}
	fedKey := *federationKeyFlag
	if envKey := os.Getenv("DOCK_RADAR_FEDERATION_KEY"); envKey != "" {
		fedKey = envKey
	}
	wanInterval := *wanSyncIntervalFlag
	if envInterval := os.Getenv("DOCK_RADAR_WAN_SYNC_INTERVAL"); envInterval != "" {
		if d, err := time.ParseDuration(envInterval); err == nil && d > 0 {
			wanInterval = d
		}
	}

	fedCfg := federation.DefaultFederationConfig()
	fedCfg.Enabled = enableFederation
	fedCfg.LocalRegionID = fedRegion
	fedCfg.LocalRegionName = fedName
	fedCfg.TunnelKey = fedKey
	if wanInterval.Seconds() >= 5 {
		fedCfg.SyncIntervalSec = int(wanInterval.Seconds())
	}

	fedEngine, err := federation.NewEngine(fedCfg, dockerClient, handlerCfg.AuditLogger, handlerCfg.AlertDispatcher)
	if err != nil {
		log.Printf("Warning: failed to initialize federation engine: %v", err)
	} else {
		handlerCfg.FederationEngine = fedEngine
		if enableFederation {
			fedCtx, fedCancel := context.WithCancel(context.Background())
			defer fedCancel()
			go fedEngine.Start(fedCtx)
		}
	}

	// Launch container vulnerability scanner & SBOM engine
	if handlerCfg != nil && handlerCfg.ScannerEngine != nil {
		scannerEnabled := *scannerFlag
		if envScan := os.Getenv("DOCK_RADAR_SCANNER_ENABLED"); envScan != "" {
			scannerEnabled = strings.EqualFold(envScan, "true") || envScan == "1"
		}
		autoScan := *scannerAutoScanFlag
		if envAuto := os.Getenv("DOCK_RADAR_SCANNER_AUTO_SCAN"); envAuto != "" {
			autoScan = strings.EqualFold(envAuto, "true") || envAuto == "1"
		}
		scanInterval := *scannerIntervalFlag
		if envInterval := os.Getenv("DOCK_RADAR_SCANNER_INTERVAL"); envInterval != "" {
			if d, err := time.ParseDuration(envInterval); err == nil && d > 0 {
				scanInterval = d
			}
		}
		gatingSev := *scannerGatingFlag
		if envGating := os.Getenv("DOCK_RADAR_SCANNER_GATING_SEVERITY"); envGating != "" {
			gatingSev = envGating
		}

		sCfg := handlerCfg.ScannerEngine.GetConfig()
		sCfg.Enabled = scannerEnabled
		sCfg.AutoScan = autoScan
		if scanInterval.Seconds() >= 5 {
			sCfg.ScanIntervalSec = int(scanInterval.Seconds())
		}
		if gatingSev != "" {
			sCfg.GatingPolicy.FailOnSeverity = scanner.ParseSeverity(gatingSev)
		}
		_ = handlerCfg.ScannerEngine.UpdateConfig(sCfg)

		if scannerEnabled {
			scannerCtx, scannerCancel := context.WithCancel(context.Background())
			defer scannerCancel()
			go handlerCfg.ScannerEngine.Start(scannerCtx)
		}
	}

	// Launch distributed rate-limiting & global quota orchestrator
	var defaultRLRPS float64 = 50.0
	if handlerCfg != nil && handlerCfg.RateLimitEngine != nil {
		rlEnabled := *ratelimitFlag
		if envRL := os.Getenv("DOCK_RADAR_RATELIMIT_ENABLED"); envRL != "" {
			rlEnabled = strings.EqualFold(envRL, "true") || envRL == "1"
		}
		rlRPS := *ratelimitRPSFlag
		if envRPS := os.Getenv("DOCK_RADAR_RATELIMIT_DEFAULT_RPS"); envRPS != "" {
			if f, err := strconv.ParseFloat(envRPS, 64); err == nil && f > 0 {
				rlRPS = f
			}
		}
		defaultRLRPS = rlRPS
		rlBurst := *ratelimitBurstFlag
		if envBurst := os.Getenv("DOCK_RADAR_RATELIMIT_BURST"); envBurst != "" {
			if b, err := strconv.Atoi(envBurst); err == nil && b > 0 {
				rlBurst = b
			}
		}
		rlAutoBan := *ratelimitAutoBanFlag
		if envBan := os.Getenv("DOCK_RADAR_RATELIMIT_AUTOBAN"); envBan != "" {
			rlAutoBan = strings.EqualFold(envBan, "true") || envBan == "1"
		}
		rlSecret := *ratelimitSecretFlag
		if envSecret := os.Getenv("DOCK_RADAR_RATELIMIT_SYNC_SECRET"); envSecret != "" {
			rlSecret = envSecret
		}

		rlCfg := handlerCfg.RateLimitEngine.Config()
		rlCfg.Enabled = rlEnabled
		rlCfg.DefaultRPS = rlRPS
		rlCfg.DefaultBurst = rlBurst
		rlCfg.AutoBanEnabled = rlAutoBan
		rlCfg.SyncSecret = rlSecret
		_ = handlerCfg.RateLimitEngine.UpdateConfig(rlCfg)

		if rlEnabled {
			rlCtx, rlCancel := context.WithCancel(context.Background())
			defer rlCancel()
			handlerCfg.RateLimitEngine.Start(rlCtx)
		}
	}

	// Launch eBPF micro-firewall & container network isolator
	if handlerCfg != nil && handlerCfg.FirewallEngine != nil {
		fwEnabled := *firewallFlag
		if envFW := os.Getenv("DOCK_RADAR_FIREWALL_ENABLED"); envFW != "" {
			fwEnabled = strings.EqualFold(envFW, "true") || envFW == "1"
		}
		fwZT := *firewallZeroTrustFlag
		if envZT := os.Getenv("DOCK_RADAR_FIREWALL_ZEROTRUST"); envZT != "" {
			fwZT = strings.EqualFold(envZT, "true") || envZT == "1"
		}
		fwPPS := *firewallDDoSPPSFlag
		if envPPS := os.Getenv("DOCK_RADAR_FIREWALL_DDOS_PPS"); envPPS != "" {
			if u, err := strconv.ParseUint(envPPS, 10, 64); err == nil && u > 0 {
				fwPPS = u
			}
		}
		fwBPS := *firewallDDoSBPSFlag
		if envBPS := os.Getenv("DOCK_RADAR_FIREWALL_DDOS_BPS"); envBPS != "" {
			if u, err := strconv.ParseUint(envBPS, 10, 64); err == nil && u > 0 {
				fwBPS = u
			}
		}
		fwAutoBan := *firewallAutoBanFlag
		if envBan := os.Getenv("DOCK_RADAR_FIREWALL_AUTOBAN"); envBan != "" {
			fwAutoBan = strings.EqualFold(envBan, "true") || envBan == "1"
		}

		fwCfg := handlerCfg.FirewallEngine.Config()
		fwCfg.Enabled = fwEnabled
		fwCfg.ZeroTrustEnabled = fwZT
		fwCfg.DDoSThresholdPPS = fwPPS
		fwCfg.DDoSThresholdBPS = fwBPS
		fwCfg.AutoQuarantineOnDDoS = fwAutoBan
		_ = handlerCfg.FirewallEngine.UpdateConfig(fwCfg)

		if fwEnabled {
			fwCtx, fwCancel := context.WithCancel(context.Background())
			defer fwCancel()
			go handlerCfg.FirewallEngine.Start(fwCtx)
		}
	}

	// Launch GitOps continuous sync & webhook auto-deployer
	if handlerCfg != nil && handlerCfg.GitOpsEngine != nil {
		gitopsEnabled := *gitopsFlag
		if envGitOps := os.Getenv("DOCK_RADAR_GITOPS_ENABLED"); envGitOps != "" {
			gitopsEnabled = strings.EqualFold(envGitOps, "true") || envGitOps == "1"
		}
		pollInterval := *gitopsPollIntervalFlag
		if envInterval := os.Getenv("DOCK_RADAR_GITOPS_POLL_INTERVAL"); envInterval != "" {
			if d, err := time.ParseDuration(envInterval); err == nil && d > 0 {
				pollInterval = d
			}
		}
		strictSig := *gitopsStrictSigFlag
		if envStrict := os.Getenv("DOCK_RADAR_GITOPS_STRICT_SIGNATURES"); envStrict != "" {
			strictSig = strings.EqualFold(envStrict, "true") || envStrict == "1"
		}
		autoRollback := *gitopsAutoRollbackFlag
		if envRollback := os.Getenv("DOCK_RADAR_GITOPS_AUTO_ROLLBACK"); envRollback != "" {
			autoRollback = strings.EqualFold(envRollback, "true") || envRollback == "1"
		}
		webhookSecret := *gitopsWebhookSecretFlag
		if envSecret := os.Getenv("DOCK_RADAR_GITOPS_WEBHOOK_SECRET"); envSecret != "" {
			webhookSecret = envSecret
		}

		gCfg := handlerCfg.GitOpsEngine.Config()
		gCfg.Enabled = gitopsEnabled
		if pollInterval.Seconds() >= 5 {
			gCfg.DefaultPollIntervalSec = int(pollInterval.Seconds())
		}
		if strictSig {
			gCfg.DefaultSignaturePolicy = gitops.PolicyStrict
		} else {
			gCfg.DefaultSignaturePolicy = gitops.PolicyWarn
		}
		gCfg.AutoRollback = autoRollback
		gCfg.DefaultWebhookSecret = webhookSecret
		_ = handlerCfg.GitOpsEngine.UpdateConfig(gCfg)

		if gitopsEnabled {
			gitopsCtx, gitopsCancel := context.WithCancel(context.Background())
			defer gitopsCancel()
			go handlerCfg.GitOpsEngine.Start(gitopsCtx)
		}
	}

	// Launch High-Availability Raft Cluster Consensus Engine
	raftEnabled := *raftFlag
	if envRaft := os.Getenv("DOCK_RADAR_RAFT_ENABLED"); envRaft != "" {
		raftEnabled = strings.EqualFold(envRaft, "true") || envRaft == "1"
	}
	raftPeers := *raftPeersFlag
	if envPeers := os.Getenv("DOCK_RADAR_RAFT_PEERS"); envPeers != "" {
		raftPeers = envPeers
	}
	raftHeartbeat := *raftHeartbeatFlag
	if envHB := os.Getenv("DOCK_RADAR_RAFT_HEARTBEAT"); envHB != "" {
		if d, err := time.ParseDuration(envHB); err == nil && d > 0 {
			raftHeartbeat = d
		}
	}
	raftElectionTimeout := *raftElectionTimeoutFlag
	if envET := os.Getenv("DOCK_RADAR_RAFT_ELECTION_TIMEOUT"); envET != "" {
		if d, err := time.ParseDuration(envET); err == nil && d > 0 {
			raftElectionTimeout = d
		}
	}
	raftDataDir := *raftDataDirFlag
	if envData := os.Getenv("DOCK_RADAR_RAFT_DATA_DIR"); envData != "" {
		raftDataDir = envData
	}

	if handlerCfg != nil && handlerCfg.RaftEngine != nil {
		rCfg := raft.DefaultRaftConfig()
		rCfg.Enabled = raftEnabled
		rCfg.NodeID = nodeName
		rCfg.BindAddr = fmt.Sprintf(":%s", port)
		rCfg.DataDir = raftDataDir
		rCfg.HeartbeatInterval = raftHeartbeat
		rCfg.ElectionTimeoutMin = raftElectionTimeout
		rCfg.ElectionTimeoutMax = raftElectionTimeout * 2

		if raftPeers != "" {
			for _, p := range strings.Split(raftPeers, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					rCfg.Peers = append(rCfg.Peers, p)
				}
			}
		}

		// Rebuild engine with populated configuration if peers or custom timings given
		var transportToken string
		if adminToken != "" {
			transportToken = adminToken
		}
		tr := raft.NewHTTPTransport(raftHeartbeat, transportToken)
		rebuiltEngine, err := raft.NewEngine(rCfg, handlerCfg.RaftEngine.FSM(), tr, handlerCfg.AuditLogger, handlerCfg.AlertDispatcher)
		if err == nil {
			handlerCfg.RaftEngine = rebuiltEngine
		}

		if raftEnabled {
			raftCtx, raftCancel := context.WithCancel(context.Background())
			defer raftCancel()
			handlerCfg.RaftEngine.Start(raftCtx)
		}
	}

	scheme := "http"
	tlsStatus := "Inactive (Plain HTTP)"

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if useTLS {
		scheme = "https"
		tlsConfig, err := security.LoadOrGenerateTLSConfig(tlsCertPath, tlsKeyPath, true, []string{"localhost"})
		if err != nil {
			log.Fatalf("TLS initialization failed: %v", err)
		}
		server.TLSConfig = tlsConfig
		if tlsCertPath != "" && tlsKeyPath != "" {
			tlsStatus = "Custom Certificate Active"
		} else {
			tlsStatus = "Auto-Generated ECDSA P-256 Self-Signed Active"
		}
	}

	// Initialize Multi-Host Agent Mesh & Remote Node Aggregator
	meshRegistry := mesh.NewRegistry("coordinator", nodeName)
	localAddr := fmt.Sprintf("%s://localhost:%s", scheme, port)
	_ = meshRegistry.Register(&mesh.Node{
		ID:      "local",
		Name:    nodeName,
		Address: localAddr,
		Labels:  map[string]string{"role": "coordinator"},
		Status:  mesh.NodeStatusOnline,
	})

	if nodesStr != "" {
		nodeAddrs := strings.Split(nodesStr, ",")
		for i, rawAddr := range nodeAddrs {
			addr := strings.TrimSpace(rawAddr)
			if addr == "" {
				continue
			}
			nodeID := fmt.Sprintf("node-%d", i+1)
			_ = meshRegistry.Register(&mesh.Node{
				ID:      nodeID,
				Name:    fmt.Sprintf("Node %d", i+1),
				Address: addr,
				Status:  mesh.NodeStatusUnknown,
			})
		}
	}

	enableDiscovery := *meshDiscoveryFlag
	if envDisc := os.Getenv("DOCK_RADAR_MESH_DISCOVERY"); envDisc != "" {
		enableDiscovery = strings.EqualFold(envDisc, "true") || envDisc == "1"
	}
	discoveryPort := *meshPortFlag
	if envPort := os.Getenv("DOCK_RADAR_MESH_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			discoveryPort = p
		}
	}
	gossipInterval := *gossipIntervalFlag
	if envGossip := os.Getenv("DOCK_RADAR_GOSSIP_INTERVAL"); envGossip != "" {
		if d, err := time.ParseDuration(envGossip); err == nil && d > 0 {
			gossipInterval = d
		}
	}

	proberToken := adminToken
	if proberToken == "" {
		proberToken = viewerToken
	}
	meshProber := mesh.NewProber(meshRegistry, mesh.ProberConfig{
		Interval: 15 * time.Second,
		Timeout:  5 * time.Second,
		Token:    proberToken,
	})

	meshDiscovery := mesh.NewDiscoveryEngine(mesh.DiscoveryConfig{
		Enabled:    enableDiscovery,
		Port:       discoveryPort,
		NodeID:     "coordinator",
		NodeName:   nodeName,
		Address:    localAddr,
		ClusterKey: "dock-radar-cluster",
	}, meshRegistry)

	meshGossip := mesh.NewGossipEngine("coordinator", nodeName, localAddr, meshRegistry, mesh.GossipConfig{
		PingInterval: gossipInterval,
		AuthToken:    proberToken,
	})

	if handlerCfg != nil {
		handlerCfg.MeshRegistry = meshRegistry
		handlerCfg.MeshProber = meshProber
		handlerCfg.MeshDiscovery = meshDiscovery
		handlerCfg.MeshGossip = meshGossip
	}

	proberCtx, proberCancel := context.WithCancel(context.Background())
	defer proberCancel()
	go meshProber.Start(proberCtx)

	discCtx, discCancel := context.WithCancel(context.Background())
	defer discCancel()
	_ = meshDiscovery.Start(discCtx)

	gossipCtx, gossipCancel := context.WithCancel(context.Background())
	defer gossipCancel()
	meshGossip.Start(gossipCtx)

	authStatus := "Disabled (Local Admin Default)"
	if tokenAuth.IsEnabled() {
		parts := []string{}
		if adminToken != "" {
			parts = append(parts, "Admin Token")
		}
		if viewerToken != "" {
			parts = append(parts, "Viewer Token")
		}
		authStatus = fmt.Sprintf("Bearer Token RBAC Active (%s)", strings.Join(parts, ", "))
	}

	storageStatusDesc := fmt.Sprintf("Ephemeral Local (%s) · S3 Standby", logStorageDir)
	if s3Cfg.IsEnabled() {
		storageStatusDesc = fmt.Sprintf("Active (%s/%s) · Local: %s", s3Endpoint, s3Bucket, logStorageDir)
	}

	ebpfStatusDesc := "Disabled"
	if handlerCfg != nil && handlerCfg.EBPFEngine != nil {
		st := handlerCfg.EBPFEngine.Status()
		if st.Enabled {
			ebpfStatusDesc = fmt.Sprintf("Active (%s · %s)", st.Mode, st.KernelVersion)
		}
	}

	federationStatusDesc := "Disabled"
	if handlerCfg != nil && handlerCfg.FederationEngine != nil {
		st := handlerCfg.FederationEngine.GetStatus()
		if st.Enabled {
			federationStatusDesc = fmt.Sprintf("Active (%s · %s · %d regions)", st.LocalRegionID, st.LocalRegionName, st.TotalRegions)
		}
	}

	scannerStatusDesc := "Disabled"
	if handlerCfg != nil && handlerCfg.ScannerEngine != nil {
		st := handlerCfg.ScannerEngine.GetStatus()
		if st.Enabled {
			scannerStatusDesc = fmt.Sprintf("Active (%d images · %d CVEs)", st.TotalScannedImages, st.TotalVulnerabilities)
		}
	}

	rateLimitStatusDesc := "Disabled"
	if handlerCfg != nil && handlerCfg.RateLimitEngine != nil {
		st := handlerCfg.RateLimitEngine.Status()
		if st.Enabled {
			rateLimitStatusDesc = fmt.Sprintf("Active (%.1f default RPS · %d active bans)", defaultRLRPS, st.ActiveBannedIPs)
		}
	}

	firewallStatusDesc := "Disabled"
	if handlerCfg != nil && handlerCfg.FirewallEngine != nil {
		st := handlerCfg.FirewallEngine.Status()
		if st.Enabled {
			firewallStatusDesc = fmt.Sprintf("Active (%d rules · %d isolated · %d quarantined)", st.TotalRules, st.IsolatedContainers, st.QuarantinedContainers)
		}
	}

	gitopsStatusDesc := "Disabled"
	if handlerCfg != nil && handlerCfg.GitOpsEngine != nil {
		st := handlerCfg.GitOpsEngine.Status()
		if st.Enabled {
			gitopsStatusDesc = fmt.Sprintf("Active (%d repos tracked · %d deployments · %d rollbacks)", st.TrackedReposCount, st.TotalDeployments, st.RolledBackDeployments)
		}
	}

	raftStatusDesc := "Disabled"
	if handlerCfg != nil && handlerCfg.RaftEngine != nil {
		st := handlerCfg.RaftEngine.Status()
		raftStatusDesc = fmt.Sprintf("Active (Role: %s · Term: %d · Quorum: %d/%d)", strings.ToUpper(st.State), st.Term, st.QuorumSize, st.PeerCount+1)
	}

	fmt.Println("=========================================================")
	fmt.Printf(" 🚀 Dock-Radar v%s · Single-Binary Container & System Monitor\n", AppVersion)
	fmt.Printf(" 📡 Web Dashboard Live at %s://localhost:%s\n", scheme, port)
	fmt.Printf(" 🔒 Transport Security : %s\n", tlsStatus)
	fmt.Printf(" 🔑 Access Control     : %s\n", authStatus)
	fmt.Printf(" 🌐 Remote Access      : %s\n", map[bool]string{true: "Allowed", false: "Restricted to Loopback"}[allowRemote])
	fmt.Printf(" 🕸️ Cluster Mesh       : %d node(s) configured (%s)\n", len(meshRegistry.List()), nodeName)
	fmt.Printf(" 📡 LAN Discovery      : %s (UDP:%d)\n", map[bool]string{true: "Active", false: "Disabled"}[enableDiscovery], discoveryPort)
	fmt.Printf(" 💬 SWIM Gossip        : Active (%s failure detection interval)\n", gossipInterval)
	fmt.Printf(" 🛡️ Self-Healing       : Autonomous Policy & Remediation Engine Active\n")
	fmt.Printf(" 🔮 Anomaly Radar      : Predictive OOM Regression & Early Warning Active\n")
	fmt.Printf(" 🔄 Rolling Restarts   : Zero-Downtime Traffic Draining & Readiness Engine Active\n")
	fmt.Printf(" 💾 Log Storage        : %s\n", storageStatusDesc)
	fmt.Printf(" ⚡ Kernel eBPF        : %s\n", ebpfStatusDesc)
	fmt.Printf(" 🌍 Edge Federation   : %s\n", federationStatusDesc)
	fmt.Printf(" 🔍 Vulnerability/SBOM : %s\n", scannerStatusDesc)
	fmt.Printf(" 🚦 Rate Limiting      : %s\n", rateLimitStatusDesc)
	fmt.Printf(" 🧱 Micro-Firewall     : %s\n", firewallStatusDesc)
	fmt.Printf(" 🚀 GitOps Deployer    : %s\n", gitopsStatusDesc)
	fmt.Printf(" 🗳️ Raft Consensus     : %s\n", raftStatusDesc)
	fmt.Println(" 💡 Embed Mode: 100% Self-Contained Zero-Dependency Binary")
	fmt.Println("=========================================================")

	var serveErr error
	if useTLS {
		serveErr = server.ListenAndServeTLS("", "")
	} else {
		serveErr = server.ListenAndServe()
	}

	if serveErr != nil && serveErr != http.ErrServerClosed {
		log.Fatalf("Server error: %v", serveErr)
	}
}
