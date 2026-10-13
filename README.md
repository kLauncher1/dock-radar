<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <b>🇺🇸 English</b> · <a href="./docs/locales/ko.md">🇰🇷 한국어</a> · <a href="./docs/locales/zh-CN.md">🇨🇳 简体中文</a> · <a href="./docs/locales/ja.md">🇯🇵 日本語</a> · <a href="./docs/locales/es.md">🇪🇸 Español</a><br />
  <a href="./docs/locales/fr.md">🇫🇷 Français</a> · <a href="./docs/locales/ru.md">🇷🇺 Русский</a> · <a href="./docs/locales/pt-BR.md">🇧🇷 Português</a> · <a href="./docs/locales/ar.md">🇸🇦 العربية</a> · <a href="./docs/locales/hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**Ultra-lightweight single-binary container & system metrics monitor with embedded real-time dark-mode web dashboard.**

[![Release](https://img.shields.io/badge/Release-v0.2.0-38bdf8.svg?style=flat)](https://github.com/kLauncher1/dock-radar/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6%2B-3178C6.svg?style=flat&logo=typescript)](https://www.typescriptlang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Memory Footprint](https://img.shields.io/badge/Memory_Footprint-<15MB-10b981.svg)](#-architecture--performance)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-quick-start)

<sub>Crafted by **kLauncher1** · Designed for minimal resource overhead on homelabs & edge nodes.</sub>

</div>

---

## ⚡ Highlights

- **Single Executable Deployment**: The web dashboard is baked directly into the Go binary via `//go:embed`. No Node.js runtime, external assets, or separate frontend servers needed.
- **Ultra-Low Memory Footprint**: Runs persistently under **15 MB of RAM**, making it ideal for low-spec VPS, Raspberry Pi, and homelab environments.
- **Docker Socket Inspection & Lifecycle Controls**: Inspects active containers and provides one-click safe container restart and stop actions with confirmation dialogs.
- **Host System Telemetry**: Tracks real-time CPU cores, goroutines, allocated RAM, GC cycles, and uptime.
- **Security-First API Defense**: Hardened with loopback origin validation, anti-CSRF checks, strict container ID regex sanitation, and in-memory token bucket rate limiting.
- **Dark-Mode Glassmorphism UI**: High-contrast, clean visual dashboard featuring live container inspection, action controls, and real-time event logs.

---

## 🚀 Quick Start

### 1. Download & Run (Standalone Binary)

```bash
# Clone the repository
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# Run directly using Go
go run .
```

The embedded web console will be accessible immediately at:
👉 **`http://localhost:9080`**

### 2. Build Single Binary

```bash
# Compiles a tiny, stripped standalone executable
go build -ldflags="-s -w" -o dock-radar .

# Run binary
./dock-radar
```

### 3. Custom Port Configuration

```bash
PORT=8080 ./dock-radar
```

---

## 🏛️ Architecture & Security

```text
┌────────────────────────────────────────────────────────┐
│                      dock-radar                        │
│                 Single Go Executable                   │
├──────────────────────────┬─────────────────────────────┤
│   internal/docker        │      internal/system        │
│   • Direct Socket Client │      • Runtime Allocations  │
│   • Lifecycle Operations │      • CPU & OS Metrics     │
├──────────────────────────┴─────────────────────────────┤
│   internal/security                                    │
│   • Loopback Origin Gate • Anti-CSRF Header Check      │
│   • Token Bucket Limiter • Input Bounds Sanitation     │
├────────────────────────────────────────────────────────┤
│                 net/http HTTP Engine                   │
│   • /api/docker          • /api/docker/restart         │
│   • /api/docker/stop     • /api/system                 │
├────────────────────────────────────────────────────────┤
│                 Embedded Web Dashboard                 │
│         (React 19 + TypeScript / Vite Bundled)         │
│          //go:embed web/dist/* -> Port 9080            │
└────────────────────────────────────────────────────────┘
```

### Security Guarantees
- **Loopback-Only Mutation Policy**: Mutating endpoints (`/api/docker/restart`, `/api/docker/stop`) strictly verify that request origins and client IPs match local loopback interfaces (`127.0.0.1`, `::1`, `localhost`).
- **Anti-CSRF & DNS Rebinding Defenses**: Modern browser metadata (`Sec-Fetch-Site`) and `Origin`/`Referer` headers are validated to prevent cross-origin drive-by attacks from malicious websites.
- **Parameter Bounds Sanitation**: All container IDs and names are evaluated against strict alphanumeric character patterns (`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`), preventing path traversal and socket injection.
- **Rate-Limiting Protection**: Token bucket rate limiter restricts container control invocations to 5 operations with a 1 token/sec refill rate, preventing daemon socket denial of service.

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/api/system` | `GET` | Hostname, OS/Arch, CPU cores, active goroutines, allocated MB, GC count, and uptime |
| `/api/docker` | `GET` | Docker daemon connection status, total & running container counts, and container details |
| `/api/docker/restart` | `POST` | Safely restarts a container by ID or name (`{"id":"<name_or_id>","timeout":10}`) |
| `/api/docker/stop` | `POST` | Safely stops a running container (`{"id":"<name_or_id>","timeout":10}`) |
| `/` | `GET` | Serves the embedded single-page web dashboard |

### Sample Response (`/api/docker/restart`)
```json
{
  "success": true,
  "action": "restart",
  "id": "c12345678901",
  "message": "container c12345678901 successfully restarted",
  "timestamp": "2026-10-13T13:25:00Z"
}
```

---

## 🗺️ Roadmap

See [ROADMAP.md](./ROADMAP.md) for milestone goals, upcoming features, and release history.

---

## 🔒 Security

For vulnerability disclosures and reporting procedures, please refer to [SECURITY.md](./SECURITY.md).

---

## 📄 License

Licensed under the [Apache License 2.0](./LICENSE).
