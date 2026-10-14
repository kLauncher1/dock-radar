<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <b>🇺🇸 English</b> · <a href="./docs/locales/ko.md">🇰🇷 한국어</a> · <a href="./docs/locales/zh-CN.md">🇨🇳 简体中文</a> · <a href="./docs/locales/ja.md">🇯🇵 日本語</a> · <a href="./docs/locales/es.md">🇪🇸 Español</a><br />
  <a href="./docs/locales/fr.md">🇫🇷 Français</a> · <a href="./docs/locales/ru.md">🇷🇺 Русский</a> · <a href="./docs/locales/pt-BR.md">🇧🇷 Português</a> · <a href="./docs/locales/ar.md">🇸🇦 العربية</a> · <a href="./docs/locales/hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**Ultra-lightweight single-binary container & system metrics monitor with embedded real-time dark-mode web dashboard.**

[![Release](https://img.shields.io/badge/Release-v1.1.0-38bdf8.svg?style=flat)](https://github.com/kLauncher1/dock-radar/releases)
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
- **Prometheus Metrics Exporter**: Native standard `/metrics` endpoint exporting host, container, engine, alert, and audit telemetry formatted according to Prometheus exposition syntax for Grafana ingestion.
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
│   internal/alert         │      internal/logs          │
│   • Discord & Slack Web  │      • Circular Ring Buffer │
│   • State Poller/Flap    │      • Strict <15MB Ceiling │
│   • Cooldown Deduplication                             │
├──────────────────────────┼─────────────────────────────┤
│   internal/metrics       │      internal/audit         │
│   • Standard Prometheus  │      • Circular Event Log   │
│   • Exposition Formatter │      • NDJSON / JSON Export │
├──────────────────────────┼─────────────────────────────┤
│   internal/security      │      net/http Router        │
│   • In-Memory ECDSA TLS  │      • /metrics (Prometheus)│
│   • Constant-Time Bearer │      • /api/docker/*        │
│   • RBAC (Admin/Viewer)  │      • /api/audit/*         │
│   • Token Bucket Limiter │      • Pure RFC 6455 WS     │
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
