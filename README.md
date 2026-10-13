<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <b>🇺🇸 English</b> · <a href="./docs/locales/ko.md">🇰🇷 한국어</a> · <a href="./docs/locales/zh-CN.md">🇨🇳 简体中文</a> · <a href="./docs/locales/ja.md">🇯🇵 日本語</a> · <a href="./docs/locales/es.md">🇪🇸 Español</a><br />
  <a href="./docs/locales/fr.md">🇫🇷 Français</a> · <a href="./docs/locales/ru.md">🇷🇺 Русский</a> · <a href="./docs/locales/pt-BR.md">🇧🇷 Português</a> · <a href="./docs/locales/ar.md">🇸🇦 العربية</a> · <a href="./docs/locales/hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**Ultra-lightweight single-binary container & system metrics monitor with embedded real-time dark-mode web dashboard.**

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
- **Docker Socket Inspection**: Directly talks to `/var/run/docker.sock` (Linux/macOS) or TCP/Named Pipes (Windows) with resilient offline fallback.
- **Host System Telemetry**: Tracks real-time CPU cores, goroutines, allocated RAM, GC cycles, and uptime.
- **Dark-Mode Glassmorphism UI**: High-contrast, clean visual dashboard featuring live container inspection, status badges, and real-time event logs.

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

## 🏛️ Architecture & Performance

```text
┌────────────────────────────────────────────────────────┐
│                      dock-radar                        │
│                 Single Go Executable                   │
├──────────────────────────┬─────────────────────────────┤
│   internal/docker        │      internal/system        │
│   • Direct Socket Client │      • Runtime Allocations  │
│   • Container Lifecycle  │      • CPU & OS Metrics     │
├──────────────────────────┴─────────────────────────────┤
│                 net/http HTTP Engine                   │
│   • /api/docker          • /api/system                 │
├────────────────────────────────────────────────────────┤
│                 Embedded Web Dashboard                 │
│         (React 19 + TypeScript / Vite Bundled)         │
│          //go:embed web/dist/* -> Port 9080            │
└────────────────────────────────────────────────────────┘
```

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/api/system` | `GET` | Hostname, OS/Arch, CPU cores, active goroutines, allocated MB, GC count, and uptime |
| `/api/docker` | `GET` | Docker daemon connection status, total & running container counts, and container details |
| `/` | `GET` | Serves the embedded single-page web dashboard |

### Sample Response (`/api/system`)
```json
{
  "hostname": "homelab-node-01",
  "os": "windows",
  "arch": "amd64",
  "num_cpu": 16,
  "num_goroutine": 4,
  "alloc_mb": 0.45,
  "total_alloc_mb": 0.54,
  "sys_mb": 11.23,
  "num_gc": 0,
  "uptime_seconds": 124,
  "collected_at": "2026-10-13T11:30:00Z"
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
