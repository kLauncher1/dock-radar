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
	"github.com/kLauncher1/dock-radar/internal/mesh"
	"github.com/kLauncher1/dock-radar/internal/security"
	"github.com/kLauncher1/dock-radar/internal/storage"
)

//go:embed web/dist/*
var embeddedWeb embed.FS

const AppVersion = "2.0.0"

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
