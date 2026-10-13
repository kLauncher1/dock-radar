# Product Roadmap

This document outlines the milestones and engineering priorities for `dock-radar`.

---

## Current Release: v0.1.0 (Foundation)
- [x] Lightweight single-binary runtime with zero external runtime dependencies.
- [x] Real-time host telemetry collector (OS, CPU cores, goroutines, allocated memory, uptime).
- [x] Docker socket inspector (`/var/run/docker.sock` and TCP fallback) with resilient offline handling.
- [x] Embedded dark-mode glassmorphism web console (`web/dist/index.html`) via Go `embed.FS`.
- [x] Automated unit test suite with sub-millisecond execution overhead.

---

## Milestone 2: v0.2.0 (Container Lifecycle Controls)
- [ ] Safe one-click container restart and stop actions via web dashboard.
- [ ] Real-time container log streaming endpoint over WebSocket.
- [ ] Configurable polling intervals and low-overhead telemetry threshold throttles.

---

## Milestone 3: v0.3.0 (Alerts & Webhooks)
- [ ] Discord and Slack webhook notifications on unexpected container termination.
- [ ] Memory and CPU threshold alerts with user-defined triggers.
- [ ] Multi-host remote agent aggregation protocol.

---

## Milestone 4: v1.0.0 (Production Hardening)
- [ ] TLS certificate auto-generation for secure remote dashboard access.
- [ ] RBAC token authentication for administrative container control endpoints.
- [ ] Cross-platform release matrix (Linux amd64/arm64, Windows x64, macOS Apple Silicon).
