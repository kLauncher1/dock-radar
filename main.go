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
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/api"
	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/mesh"
	"github.com/kLauncher1/dock-radar/internal/security"
)

//go:embed web/dist/*
var embeddedWeb embed.FS

const AppVersion = "1.5.0"

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

	mux := http.NewServeMux()
	handlerCfg := api.RegisterRoutesWithSecurity(mux, dockerClient, subFS, tokenAuth, allowRemote)
	if handlerCfg != nil {
		handlerCfg.AppVersion = AppVersion
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

	proberToken := adminToken
	if proberToken == "" {
		proberToken = viewerToken
	}
	meshProber := mesh.NewProber(meshRegistry, mesh.ProberConfig{
		Interval: 15 * time.Second,
		Timeout:  5 * time.Second,
		Token:    proberToken,
	})

	if handlerCfg != nil {
		handlerCfg.MeshRegistry = meshRegistry
		handlerCfg.MeshProber = meshProber
	}

	proberCtx, proberCancel := context.WithCancel(context.Background())
	defer proberCancel()
	go meshProber.Start(proberCtx)

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

	fmt.Println("=========================================================")
	fmt.Printf(" 🚀 Dock-Radar v%s · Single-Binary Container & System Monitor\n", AppVersion)
	fmt.Printf(" 📡 Web Dashboard Live at %s://localhost:%s\n", scheme, port)
	fmt.Printf(" 🔒 Transport Security : %s\n", tlsStatus)
	fmt.Printf(" 🔑 Access Control     : %s\n", authStatus)
	fmt.Printf(" 🌐 Remote Access      : %s\n", map[bool]string{true: "Allowed", false: "Restricted to Loopback"}[allowRemote])
	fmt.Printf(" 🕸️ Cluster Mesh       : %d node(s) configured (%s)\n", len(meshRegistry.List()), nodeName)
	fmt.Printf(" 🛡️ Self-Healing       : Autonomous Policy & Remediation Engine Active\n")
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
