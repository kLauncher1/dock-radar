# Product Roadmap

This document outlines the milestones and engineering priorities for `dock-radar`.

---

## Current Release: v0.4.0 (Automated Webhook Alerts & Health Monitors)
- [x] Lightweight single-binary runtime with zero external runtime dependencies.
- [x] Real-time host telemetry collector (OS, CPU cores, goroutines, allocated memory, uptime).
- [x] Docker socket inspector (`/var/run/docker.sock` and TCP fallback) with resilient offline handling.
- [x] Embedded dark-mode glassmorphism web console (`web/dist/index.html`) via Go `embed.FS`.
- [x] Safe one-click container restart and stop actions via web dashboard with confirmation modal dialogs.
- [x] Rate-limiting and loopback origin validation guards to defend against CSRF and socket abuse.
- [x] Real-time container log streaming over WebSocket (`/api/docker/logs`) with REST JSON snapshot fallback.
- [x] Auto-scrolling terminal feed widget with stdout/stderr/system filter tabs and container targeting.
- [x] Low-overhead in-memory ring buffer limiting log memory consumption to under 15 MB.
- [x] Automated Discord and Slack outgoing webhook triggers on container exit or crash events.
- [x] Sliding window restart flapping detection with configurable failure frequency counters.
- [x] Host memory and CPU threshold monitoring with automated alert dispatch and cooldown delays.
- [x] Embedded dashboard Alerts panel for live webhook testing, rule persistence, and incident inspection.
- [x] Automated unit and integration test suites with sub-millisecond execution overhead.

---

## Milestone 5: v1.0.0 (Production Hardening)
- [ ] TLS certificate auto-generation for encrypted remote dashboard transport.
- [ ] Bearer token authentication and role-based access controls for remote control endpoints.
- [ ] Cross-platform release matrix (Linux amd64/arm64, Windows x64, macOS Apple Silicon).

---

## Milestone 6: v1.1.0 (Metrics Export & Operations)
- [ ] Prometheus metrics exporter endpoint (`/metrics`) for Grafana scraping.
- [ ] Batch container actions (restart all running, prune exited containers).
- [ ] Audit trail event exporter in NDJSON format.

---

## Milestone 7: v1.2.0 (Multi-Host Agent Mesh)
- [ ] Lightweight node discovery protocol for monitoring multi-host Docker clusters.
- [ ] Peer heartbeat ping and unified multi-node container telemetry dashboard.
- [ ] Node label tagging and aggregate CPU/RAM metrics calculation across nodes.

---

## Milestone 8: v1.3.0 (Interactive Web Terminal Exec)
- [ ] Interactive in-browser container shell execution via WebSocket (`/api/docker/exec`).
- [ ] VT100 / ANSI escape sequence rendering with custom terminal font styling.
- [ ] Read-only shell access policy mode and idle session termination timeouts.

---

## Milestone 9: v1.4.0 (Docker Compose Topology & Stack Visualizer)
- [ ] Automatic grouping of containers by `com.docker.compose.project` labels.
- [ ] Interactive canvas rendering service dependencies and network routing.
- [ ] One-click whole-stack lifecycle actions (up, down, restart).

---

## Milestone 10: v1.5.0 (Autonomous Self-Healing Container Policies)
- [ ] Automatic remediation triggers for OOM-killed (`exit 137`) or crash-looping containers.
- [ ] Exponential backoff jitter preventing daemon saturation during cascading service failures.
- [ ] Structured remediation audit logging and rollback protection.

