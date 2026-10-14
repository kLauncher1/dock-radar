# Product Roadmap

This document outlines the architectural milestones and engineering priorities for `dock-radar`.

---

## Current Release: v1.0.0 (Production Hardening & Multi-Platform Matrix)
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
- [x] Automatic TLS certificate generation with ECDSA P-256 self-signed certificates and modern TLS 1.2+ ciphers.
- [x] Bearer token authentication and role-based access control (Admin vs Read-Only Viewer) with constant-time verification.
- [x] In-browser security credentials manager with token persistence and live role status pills.
- [x] Multi-architecture cross-compilation pipeline covering Linux amd64/arm64, macOS amd64/arm64, and Windows amd64.
- [x] Automated unit and integration test suites with sub-millisecond execution overhead.

---

## Milestone 6: v1.1.0 (Metrics Export & Operations)
- [x] Prometheus metrics exporter endpoint (`/metrics`) for Grafana scraping.
- [x] Batch container actions (restart all running, prune exited containers).
- [x] Audit trail event exporter in NDJSON format.

---

## Milestone 7: v1.2.0 (Multi-Host Agent Mesh & Remote Node Aggregator)
- [x] Lightweight node discovery protocol for monitoring multi-host Docker clusters (`internal/mesh/node.go`, `internal/mesh/prober.go`).
- [x] Peer heartbeat ping and unified multi-node container telemetry dashboard (`/api/nodes`, `/api/nodes/heartbeat`, `/api/cluster/containers`).
- [x] Node label tagging and aggregate CPU/RAM metrics calculation across nodes (`/api/cluster/summary`, Prometheus `/metrics`).

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

## Milestone 10: v1.5.0 (Self-Healing Container Remediation Engine)
- [ ] Automatic remediation triggers for OOM-killed (`exit 137`) or crash-looping containers.
- [ ] Exponential backoff jitter preventing daemon saturation during cascading service failures.
- [ ] Structured remediation audit logging and rollback protection.

---

## Milestone 11: v1.6.0 (Predictive Resource Exhaustion Alarms)
- [ ] Linear regression trend analyzer forecasting container memory saturation.
- [ ] Early-warning webhook notifications prior to kernel OOM invocation.
- [ ] Interactive visual exhaustion meters on container overview cards.

---

## Milestone 12: v1.7.0 (Zero-Config LAN Peer Synchronization)
- [ ] UDP broadcast discovery for auto-detecting nearby dock-radar daemon nodes.
- [ ] Gossip-based state exchange for multi-server cluster metrics.
- [ ] Unified multi-host aggregated view in the embedded dashboard.

---

## Milestone 13: v1.8.0 (Zero-Downtime Rolling Restarts)
- [ ] Staggered sequential container restarts with health check readiness probing.
- [ ] Traffic draining and reverse proxy health status integration.
- [ ] Configurable batch concurrency limit and rollback abort triggers.

---

## Milestone 14: v1.9.0 (Distributed Ephemeral Log Storage & S3 Offloader)
- [ ] Compressed log chunking and local ring buffer rotation to disk.
- [ ] Background asynchronous offloader streaming logs to S3-compatible object stores (MinIO, AWS S3, Cloudflare R2).
- [ ] Ephemeral retention policies with automatic cold storage tiering.

---

## Milestone 15: v2.0.0 (Adaptive Kernel eBPF Telemetry Engine)
- [ ] Low-overhead network socket and system call tracing via eBPF probes.
- [ ] Real-time container TCP connection flow graphs and bandwidth consumption meters.
- [ ] Kernel-level security anomaly detection with automated alert triggers.

---

## Milestone 16: v2.1.0 (Multi-Region Edge Peer Federation & WAN Sync)
- [ ] Edge mesh federation with encrypted overlay tunnels for cross-region node synchronization.
- [ ] Low-bandwidth delta sync protocol optimized for high-latency WAN connections.
- [ ] Geo-distributed container inventory routing with failover policy triggers.

