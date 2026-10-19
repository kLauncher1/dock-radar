<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <b>🇺🇸 English</b> · <a href="./docs/locales/ko.md">🇰🇷 한국어</a> · <a href="./docs/locales/zh-CN.md">🇨🇳 简体中文</a> · <a href="./docs/locales/ja.md">🇯🇵 日本語</a> · <a href="./docs/locales/es.md">🇪🇸 Español</a><br />
  <a href="./docs/locales/fr.md">🇫🇷 Français</a> · <a href="./docs/locales/ru.md">🇷🇺 Русский</a> · <a href="./docs/locales/pt-BR.md">🇧🇷 Português</a> · <a href="./docs/locales/ar.md">🇸🇦 العربية</a> · <a href="./docs/locales/hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**Ultra-lightweight single-binary container & system metrics monitor with embedded real-time dark-mode web dashboard.**

[![Release](https://img.shields.io/badge/Release-v2.3.0-38bdf8.svg?style=flat)](https://github.com/kLauncher1/dock-radar/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6%2B-3178C6.svg?style=flat&logo=typescript)](https://www.typescriptlang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Memory Footprint](https://img.shields.io/badge/Memory_Footprint-<15MB-10b981.svg)](#-architecture--performance)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-quick-start)

<sub>Crafted by **kLauncher1** · Designed for minimal resource overhead on homelabs, servers & edge nodes.</sub>

</div>

---

## ⚡ Highlights

- **Single Executable Deployment**: The web dashboard is baked directly into the Go binary via `//go:embed`. No Node.js runtime, external assets, or separate frontend servers needed.
- **Ultra-Low Memory Footprint**: Runs persistently under **15 MB of RAM** with bounded circular ring buffers, making it ideal for low-spec VPS, Raspberry Pi, and homelab environments.
- **Distributed Rate-Limiting & Global Quota Orchestrator**: Thread-safe token bucket and sliding-window rate limiters with fractional refill intervals, burst capacities, and bandwidth throttling controls. Features automated abuse mitigation and IP ban propagation (`IPBanTracker`) with configurable violation thresholds and local loopback immunity, cross-node HMAC-SHA256 authenticated peer sync protocol with 60-second replay attack defense, Prometheus rate-limiting exporter gauges, and interactive dark-mode dashboard management tables.
- **Container Image Vulnerability Scanner & SBOM Audit**: In-line container image layer analysis and curated multi-ecosystem vulnerability database lookup covering Alpine (`apk`), Debian (`deb`), Go, NPM, and PyPI packages. Features automated Software Bill of Materials (SBOM) generation supporting both SPDX 2.3 and CycloneDX 1.5 JSON standards with pURL formatting, automated deployment security gating policy evaluator with configurable critical/high thresholds and license compliance policies, interactive live dashboard audit table, and one-click SBOM export.
- **Multi-Region Edge Peer Federation & WAN Sync**: Secure cross-region edge mesh federation over AES-256-GCM encrypted overlay tunnels authenticated via HMAC-SHA256 signatures with 60-second replay attack defense. Features low-bandwidth delta sync protocol utilizing SHA-256 inventory digests and gzip compression, Haversine spherical distance geo-routing, automated failover triggers on consecutive probe failures with probation recovery windows, and dedicated edge federation views in the embedded dark-mode web dashboard.
- **Adaptive Kernel eBPF Telemetry & Behavioral Security Engine**: Pure standard-library socket flow tracker and Linux `/proc/net/tcp` inspector measuring real-time TCP/UDP socket connections, byte throughput, and round-trip latency. Built-in behavioral security engine monitors container system calls with automated detection rules for unexpected shell execution (`execve`), privilege escalation (`setuid`), memory inspection (`ptrace`), sensitive host credential access (`/etc/shadow`), Docker socket abuse, and outbound mining connections, paired with a live visual flow monitor and incident mitigation feed.
- **Distributed Ephemeral Log Storage & S3 Offloader**: Compresses in-memory container logs into gzip (`.gz`) chunks with cryptographic SHA-256 integrity checksums and atomic disk writing. Background asynchronous offloader streams chunk archives to S3-compatible cloud object storage (AWS S3, MinIO, Cloudflare R2) using a zero-dependency pure standard-library AWS SigV4 signer. Includes local disk capacity caps, age-based rotation, offload-priority retention pruning, and dedicated chunk explorer table with direct gzip download.
- **Zero-Downtime Rolling Restarts & Traffic Draining**: Orchestrates staggered sequential container restarts across replicas, Compose stacks, or label groups. Incorporates graceful in-flight traffic draining with configurable timeouts and reverse proxy webhook notification, multi-stage container readiness probing (Docker state, container healthcheck, HTTP `/healthz` endpoints, readiness grace windows), and automated rollback abort triggers preventing downtime during cascading failures.
- **Dynamic Multi-Node Cluster Mesh & Gossip Discovery**: Zero-configuration LAN UDP broadcast auto-discovery (port 9085) paired with a lightweight SWIM-based gossip protocol. Features direct randomized ping/ack, indirect helper pings ($k=3$), suspicion watchdog timers, incarnation refutation, and decentralized cluster health consensus with dedicated multi-host cards in the web dashboard.
- **Predictive Anomaly Detection & OOM Exhaustion Radar**: Real-time Ordinary Least Squares (OLS) linear regression trend analysis forecasting memory saturation slope ($m$), intercept ($c$), and dynamic Time-to-Exhaustion (TTE). Early-warning webhook notifications fire before kernel OOM killer terminates containers, paired with glowing countdown meters and trend cards in the web dashboard.
- **Autonomous Self-Healing Container Engine**: Automated remediation rules triggering container recovery on out-of-memory crashes (`exit 137`) and unhealthy flapping states, protected by exponential backoff jitter, circuit-breaking quarantine thresholds, and real-time Prometheus healing telemetry.
- **Docker Compose Topology & Stack Visualizer**: Automatic grouping of containers by `com.docker.compose.project` labels with interactive SVG dependency topology graphs, architectural service tier detection (database, cache, queue, gateway, worker), whole-stack lifecycle actions (restart, stop, recreate), and dedicated Prometheus stack metrics.
- **Interactive In-Browser Container Terminal (Exec)**: Full duplex interactive shell terminal over WebSocket (`/api/docker/exec`) featuring high-fidelity VT100 / ANSI escape sequence rendering (256 colors), custom font styling, read-only policy enforcement, and idle session auto-termination.
- **Multi-Host Agent Mesh & Remote Node Aggregator**: Real-time cross-host container monitoring across multi-server topologies. Dynamic node registration, peer health probing, round-trip latency tracking, and unified multi-node container telemetry.
- **Prometheus Metrics Exporter**: Native standard `/metrics` endpoint exporting host, container, mesh nodes, alert, and audit telemetry formatted according to Prometheus exposition syntax for Grafana ingestion.
- **Batch Container Operations**: One-click and API-driven synchronized lifecycle operations (`restart_all`, `stop_all`) and automatic inactive container purging (`prune`) with fallback resilience.
- **Thread-Safe Audit Trail Logging**: Fixed-capacity circular buffer recording up to 2,000 security and administrative actions with streaming NDJSON and JSON export (`/api/audit/export`).
- **Automatic TLS Transport Security**: In-memory TLS certificate engine auto-generates self-signed ECDSA P-256 certificates with Subject Alternative Names (SANs) for localhost, loopbacks, and network interfaces with modern TLS 1.2+ cipher suites. Custom certificates are fully supported via CLI flags and environment variables.
- **Bearer Token Authentication & RBAC**: Granular Role-Based Access Control distinguishing `admin` (full lifecycle control, alert rules, log feeds) and `viewer` (read-only telemetry and log feeds) with constant-time token comparison against timing side-channel attacks.
- **Automated Webhook Alerts**: Instant outgoing webhook notifications to Discord (rich color-coded embeds) and Slack (formatted attachments) on unexpected container exit, crash, or restart loops.
- **Failure Frequency & Flapping Detection**: Sliding window surveillance tracks rapid container restart cycles to detect flapping and crash-looping services before server outages occur.
- **Host Resource Threshold Surveillance**: Configurable CPU usage and memory consumption thresholds with automated alert deduplication and cooldown controls.
- **Real-Time Container Log Streaming**: Pure standard-library RFC 6455 WebSocket streaming (`/api/docker/logs`) with Docker multiplexed stdout/stderr demuxing and REST JSON snapshot fallback.
- **Docker Socket Inspection & Lifecycle Controls**: Inspects active containers and provides one-click safe container restart, stop, and batch actions with confirmation dialogs.
- **Host System Telemetry**: Tracks real-time CPU cores, goroutines, allocated RAM, GC cycles, and uptime.
- **Multi-Platform Binary Matrix**: Built and verified for Linux (amd64, arm64), macOS (amd64, arm64 Apple Silicon), and Windows (amd64).

---

## 🚀 Quick Start

### 1. Download & Run (Standalone Binary)

```bash
# Clone the repository
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# Run directly using Go (default HTTP port 9080)
go run .
```

The embedded web console will be accessible immediately at:
👉 **`http://localhost:9080`**

### 2. Run with TLS & Authentication (Production Hardened)

```bash
# Enable automatic self-signed TLS and set an admin access token
go run . --tls --admin-token="my-super-secret-admin-token" --viewer-token="my-readonly-token"
```

The secure web console will be accessible at:
👉 **`https://localhost:9080`**

### 3. Build Single Binary

```bash
# Compiles a tiny, stripped standalone executable
go build -ldflags="-s -w" -o dock-radar .

# Run binary
./dock-radar --help
```

### 4. Configuration Options & Environment Variables

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `--port` | `PORT` | `9080` | TCP port for dashboard and API listener |
| `--tls` | `DOCK_RADAR_TLS` | `false` | Enable HTTPS transport with auto-generated or custom cert |
| `--tls-cert` | `DOCK_RADAR_TLS_CERT` | `""` | Path to custom TLS certificate PEM |
| `--tls-key` | `DOCK_RADAR_TLS_KEY` | `""` | Path to custom TLS private key PEM |
| `--admin-token` | `DOCK_RADAR_ADMIN_TOKEN` | `""` | Bearer token granting full administrative control |
| `--viewer-token` | `DOCK_RADAR_VIEWER_TOKEN`| `""` | Bearer token granting read-only telemetry access |
| `--allow-remote` | `DOCK_RADAR_ALLOW_REMOTE`| `false` | Permit remote network requests without loopback check |
| `--nodes` | `DOCK_RADAR_NODES` | `""` | Comma-separated list of remote dock-radar nodes to aggregate |
| `--node-name` | `DOCK_RADAR_NODE_NAME` | `hostname` | Human-readable display name for this node |
| `--mesh-discovery` | `DOCK_RADAR_MESH_DISCOVERY` | `false` | Enable zero-config UDP broadcast LAN peer auto-discovery |
| `--mesh-port` | `DOCK_RADAR_MESH_PORT` | `9085` | UDP port for LAN peer auto-discovery beacons |
| `--gossip-interval` | `DOCK_RADAR_GOSSIP_INTERVAL` | `5s` | Ping interval for SWIM decentralized cluster gossip |
| `--federation` | `DOCK_RADAR_FEDERATION` | `false` | Enable multi-region edge peer federation and WAN sync |
| `--federation-region` | `DOCK_RADAR_FEDERATION_REGION` | `default` | Local region identifier (e.g., us-east, eu-west, ap-northeast) |
| `--federation-name` | `DOCK_RADAR_FEDERATION_NAME` | `Region` | Human-readable display name for the local edge region |
| `--federation-key` | `DOCK_RADAR_FEDERATION_KEY` | `""` | Shared secret key for HMAC-SHA256 authenticated AES-256-GCM overlay tunnels |
| `--wan-sync-interval` | `DOCK_RADAR_WAN_SYNC_INTERVAL` | `30s` | WAN delta sync interval for edge container inventory exchange |
| `--scanner` | `DOCK_RADAR_SCANNER` | `false` | Enable container image vulnerability scanner and SBOM audit engine |
| `--scanner-auto-scan` | `DOCK_RADAR_SCANNER_AUTO_SCAN` | `true` | Automatically scan active containers during background scan loops |
| `--scanner-interval` | `DOCK_RADAR_SCANNER_INTERVAL` | `1h` | Periodic background vulnerability scan sweep interval |
| `--scanner-gating-severity` | `DOCK_RADAR_SCANNER_GATING_SEVERITY` | `CRITICAL` | Maximum vulnerability severity threshold triggering deployment gating failures |
| `--ratelimit` | `DOCK_RADAR_RATELIMIT` | `false` | Enable distributed rate-limiting and global quota orchestrator |
| `--ratelimit-default-rps` | `DOCK_RADAR_RATELIMIT_DEFAULT_RPS` | `100.0` | Default requests-per-second refill rate for tenant token buckets |
| `--ratelimit-burst` | `DOCK_RADAR_RATELIMIT_BURST` | `200` | Default burst capacity tokens for tenant rate limiters |
| `--ratelimit-autoban` | `DOCK_RADAR_RATELIMIT_AUTOBAN` | `true` | Automatically ban IP addresses exceeding abusive violation thresholds |
| `--ratelimit-sync-secret` | `DOCK_RADAR_RATELIMIT_SYNC_SECRET` | `""` | Shared secret key for HMAC-SHA256 authenticated peer rate-limit sync |
| `--firewall` | `DOCK_RADAR_FIREWALL` | `false` | Enable eBPF micro-firewall and zero-trust container network isolator |
| `--firewall-zerotrust` | `DOCK_RADAR_FIREWALL_ZEROTRUST` | `true` | Enforce zero-trust default drop policy for inter-container traffic |
| `--firewall-ddos-pps` | `DOCK_RADAR_FIREWALL_DDOS_PPS` | `25000` | Ingress packets-per-second threshold triggering DDoS rate throttling |
| `--firewall-ddos-bps` | `DOCK_RADAR_FIREWALL_DDOS_BPS` | `104857600` | Ingress bytes-per-second threshold (100MB/s) triggering DDoS mitigation |
| `--firewall-autoban` | `DOCK_RADAR_FIREWALL_AUTOBAN` | `true` | Automatically quarantine containers generating abusive volumetric traffic |
| `--version` | — | — | Print dock-radar version and exit |

---

## 🏛️ Architecture & Security

```text
┌────────────────────────────────────────────────────────┐
│                      dock-radar                        │
│                 Single Go Executable                   │
├──────────────────────────┬─────────────────────────────┤
│   internal/docker        │      internal/system        │
│   • Direct Socket Client │      • Runtime Allocations  │
│   • Lifecycle & Batch Ops│      • CPU & OS Metrics     │
│   • Multiplex Log Demux  │                             │
├──────────────────────────┼─────────────────────────────┤
│   internal/ratelimit     │      internal/scanner       │
│   • Token Bucket / Slide │      • Layer CVE Scanner    │
│   • IP Ban Engine / Sync │      • SPDX 2.3 & CycloneDX │
│   • HMAC Peer Protection │      • Deployment Gating    │
├──────────────────────────┼─────────────────────────────┤
│   internal/ebpf          │      internal/federation    │
│   • Socket Flow Tracker  │      • AES-256-GCM Tunnels  │
│   • Syscall Threat Rules │      • WAN Delta Sync SHA256│
│   • /proc/net/tcp Probe  │      • Geo Haversine Router │
├──────────────────────────┼─────────────────────────────┤
│   internal/alert         │      internal/storage       │
│   • Discord & Slack Web  │      • Compressed Gzip Chunks
│   • State Poller/Flap    │      • AWS SigV4 Signer     │
│   • Cooldown Deduplication      • S3 / MinIO Offload   │
├──────────────────────────┼─────────────────────────────┤
│   internal/healing       │      internal/mesh          │
│   • Auto OOM / Crash Loop│      • Node Discovery/Probe │
│   • Jitter & Backoff     │      • SWIM Gossip Protocol │
│   • Circuit Breaker      │      • UDP Broadcast Beacon │
├──────────────────────────┼─────────────────────────────┤
│   internal/metrics       │      net/http Router        │
│   • Standard Prometheus  │      • /metrics (Prometheus)│
│   • Exposition Formatter │      • /api/docker/*        │
│   • Multi-Region Gauges  │      • /api/ratelimit/*     │
├──────────────────────────┤      • /api/firewall/*      │
│   internal/security      │      • /api/scanner/*       │
│   • In-Memory ECDSA TLS  │      • /api/federation/*    │
│   • Constant-Time Bearer │      • /api/storage/*       │
│   • RBAC (Admin/Viewer)  │      • /api/ebpf/*          │
│   internal/firewall      │      • /api/healing/*       │
│   • eBPF Packet Filter   │                             │
│   • Zero-Trust Isolator  │                             │
│   • DDoS Rate Throttler  │                             │
├──────────────────────────┴─────────────────────────────┤
│                 Embedded Web Dashboard                 │
│         (React 19 + TypeScript / Vite Bundled)         │
│          //go:embed web/dist/* -> Port 9080            │
└────────────────────────────────────────────────────────┘
```

### Security Guarantees
- **Transport Encryption (TLS)**: Supports in-memory ECDSA P-256 self-signed certificate generation with SAN validation for all host network interfaces, or custom enterprise certificate bundles.
- **Constant-Time Authentication**: Token verification relies on `crypto/subtle.ConstantTimeCompare`, neutralizing timing side-channel attacks on API tokens.
- **Granular RBAC**: Read endpoints (system metrics, container list, log streams) are accessible to `viewer` and `admin` roles, while destructive actions (restart, stop, alert mutations) strictly require `admin`.
- **Loopback Default Policy**: When authentication tokens are not configured, mutating endpoints are strictly restricted to local loopback interfaces (`127.0.0.1`, `::1`, `localhost`).
- **Anti-CSRF & DNS Rebinding Defenses**: Modern browser metadata (`Sec-Fetch-Site`) and `Origin`/`Referer` headers are validated to prevent cross-origin drive-by attacks from malicious websites.
- **Anti-SSRF & Metadata Gating**: Webhook destinations enforce strict HTTP/HTTPS schemes, filter CRLF and control characters, and explicitly reject cloud instance metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
- **Parameter Bounds Sanitation**: All container IDs and names are evaluated against strict alphanumeric character patterns (`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`), preventing path traversal and socket injection.
- **Rate-Limiting Protection**: Token bucket rate limiter restricts container and alert control invocations to 5 operations with a 1 token/sec refill rate.

---

## 📡 REST & WebSocket API Reference

| Endpoint | Method / Protocol | Required Role | Description |
| :--- | :---: | :---: | :--- |
| `/metrics` | `GET` | `viewer` | Standard Prometheus exposition metrics for Grafana scraping |
| `/api/system` | `GET` | `viewer` | Hostname, OS/Arch, CPU cores, active goroutines, allocated MB, GC count, and uptime |
| `/api/docker` | `GET` | `viewer` | Docker daemon connection status, total & running container counts, and container details |
| `/api/docker/batch` | `POST` | `admin` | Batch container operations: `restart_all`, `stop_all`, `prune` (`{"action":"restart_all","timeout":10}`) |
| `/api/docker/logs` | `WS` / `GET` | `viewer` | Real-time WebSocket log feed or JSON snapshot (`?id=<id>&stream=<stdout\|stderr\|system>&tail=100`) |
| `/api/docker/restart` | `POST` | `admin` | Safely restarts a container by ID or name (`{"id":"<name_or_id>","timeout":10}`) |
| `/api/docker/stop` | `POST` | `admin` | Safely stops a running container (`{"id":"<name_or_id>","timeout":10}`) |
| `/api/ratelimit/status` | `GET` | `viewer` | Overall rate limiter engine status, tenant counts, active bans, and sync metrics |
| `/api/ratelimit/tenants` | `GET` / `POST` / `DELETE` | `viewer` / `admin` | Lists, configures, or removes per-tenant RPS, burst limits, and bandwidth throttles |
| `/api/ratelimit/bans` | `GET` / `POST` / `DELETE` | `viewer` / `admin` | Lists active IP ban records, manually bans an IP, or unbans an IP address |
| `/api/ratelimit/sync` | `POST` | `admin` | Ingests and processes HMAC-SHA256 authenticated peer rate-limit and ban sync packets |
| `/api/ratelimit/config` | `GET` / `POST` | `viewer` / `admin` | Fetches or updates rate limiter configuration with masked sync secret |
| `/api/firewall/status` | `GET` | `viewer` | eBPF micro-firewall engine state, active rule count, isolated containers, and telemetry |
| `/api/firewall/rules` | `GET` / `POST` / `DELETE` | `viewer` / `admin` | Lists active packet rules, deploys new priority filtering rule, or removes rule |
| `/api/firewall/isolation` | `GET` / `POST` | `viewer` / `admin` | Lists container quarantine states, or places a target container into zero-trust isolation |
| `/api/firewall/isolation/unisolate` | `POST` | `admin` | Restores an isolated container back into nominal cluster network fabric |
| `/api/firewall/bandwidth` | `GET` | `viewer` | Real-time container ingress/egress BPS and PPS bandwidth throughput inspector |
| `/api/firewall/ddos/alerts` | `GET` | `viewer` | Volumetric DDoS flood detection events and auto-mitigation incident telemetry |
| `/api/firewall/simulate` | `POST` | `admin` | Evaluates a synthetic packet payload through the eBPF filter pipeline with sub-microsecond latency |
| `/api/firewall/config` | `GET` / `POST` | `viewer` / `admin` | Fetches or updates micro-firewall settings, DDoS thresholds, and zero-trust policies |
| `/api/scanner/status` | `GET` | `viewer` | Overall vulnerability scanner engine status, scan counts, and gating metrics |
| `/api/scanner/reports` | `GET` | `viewer` | Recent container image vulnerability scan reports (`?container=&image=&limit=50`) |
| `/api/scanner/report` | `GET` | `viewer` | Detailed vulnerability report for a specific container or image (`?id=&image=`) |
| `/api/scanner/scan` | `POST` | `admin` | Triggers on-demand vulnerability scan for an image or full sweep (`{"image":"alpine:latest"}`) |
| `/api/scanner/sbom` | `GET` | `viewer` | Exports downloadable SPDX 2.3 or CycloneDX 1.5 JSON SBOM (`?id=&format=spdx`) |
| `/api/scanner/gating` | `GET` / `POST` | `viewer` / `admin` | Fetches or updates automated deployment gating policies and thresholds |
| `/api/healing/config` | `GET` / `POST` | `viewer` / `admin` | Fetches or updates auto-remediation policy, jitter limits, and exclusion rules |
| `/api/healing/status` | `GET` | `viewer` | Active healing metrics, quarantined containers, and backoff states |
| `/api/healing/history`| `GET` | `viewer` | Recent remediation event history log (`?limit=50&container=`) |
| `/api/healing/reset`  | `POST` | `admin` | Clears quarantine circuit breaker and resets backoff counters for a container |
| `/api/nodes` | `GET` / `POST` / `DELETE` | `viewer` / `admin` | Node inventory list, dynamic node registration, and node unregistration |
| `/api/nodes/heartbeat` | `POST` | `viewer` | Remote agent telemetry and container synchronization push endpoint |
| `/api/cluster/summary` | `GET` | `viewer` | Aggregate cluster metrics (total/online/offline nodes, CPU, memory, container totals) |
| `/api/cluster/containers` | `GET` | `viewer` | Unified container inventory across all cluster nodes (`?node_id=&state=`) |
| `/api/mesh/discovery` | `GET` / `POST` | `viewer` / `admin` | LAN UDP auto-discovery peer status and manual beacon trigger (`POST {"action":"broadcast"}`) |
| `/api/mesh/gossip` | `GET` / `POST` | `viewer` / `none` | Cluster SWIM gossip membership state and P2P gossip message ingestion |
| `/api/federation/status` | `GET` | `viewer` | Local region info, active peer regions, and WAN synchronization status |
| `/api/federation/regions` | `GET` / `POST` / `DELETE` | `viewer` / `admin` | Edge peer region inventory, dynamic endpoint registration, and deletion |
| `/api/federation/sync` | `POST` | `admin` | Ingests and processes WAN delta sync payloads between regions |
| `/api/federation/routes` | `GET` | `viewer` | Resolves optimal geo-routing paths and failover states for containers |
| `/api/federation/failover` | `POST` | `admin` | Triggers manual or simulated failover drills across edge regions |
| `/api/federation/config` | `GET` / `POST` | `viewer` / `admin` | Fetches or updates federation settings and masked tunnel secret key |
| `/api/audit/export` | `GET` | `viewer` | Exports audit log trail in NDJSON or JSON format (`?format=ndjson&limit=2000&action=`) |
| `/api/alerts/config` | `GET` / `POST` | `viewer` / `admin` | Fetches or updates active alert rules, webhook destinations, and threshold limits |
| `/api/alerts/events` | `GET` | `viewer` | Fetches recent incident and fired alert history buffer (`?limit=50`) |
| `/api/alerts/test` | `POST` | `admin` | Dispatches an immediate test webhook verification payload to Discord or Slack |
| `/api/auth/status` | `GET` | `none` | Returns TLS status, remote access mode, authentication requirements, and current role |
| `/api/auth/verify` | `POST` | `none` | Validates a client Bearer token and returns the granted access role |
| `/` | `GET` | `none` | Serves the embedded single-page web dashboard |

---

## 🗺️ Roadmap

See [ROADMAP.md](./ROADMAP.md) for milestone goals, upcoming features, and release history.

---

## 🔒 Security

For vulnerability disclosures and reporting procedures, please refer to [SECURITY.md](./SECURITY.md).

---

## 📄 License

Licensed under the [Apache License 2.0](./LICENSE).
