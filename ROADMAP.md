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
- [x] Interactive in-browser container shell execution via WebSocket (`/api/docker/exec`).
- [x] VT100 / ANSI escape sequence rendering with custom terminal font styling.
- [x] Read-only shell access policy mode and idle session termination timeouts.

---

## Milestone 9: v1.4.0 (Docker Compose Topology & Stack Visualizer)
- [x] Automatic grouping of containers by `com.docker.compose.project` labels.
- [x] Interactive canvas rendering service dependencies and network routing.
- [x] One-click whole-stack lifecycle actions (up, down, restart).

---

## Milestone 10: v1.5.0 (Self-Healing Container Remediation Engine)
- [x] Automatic remediation triggers for OOM-killed (`exit 137`) or crash-looping containers.
- [x] Exponential backoff jitter preventing daemon saturation during cascading service failures.
- [x] Structured remediation audit logging and rollback protection.

---

## Milestone 11: v1.6.0 (Predictive Resource Exhaustion Alarms)
- [x] Linear regression trend analyzer forecasting container memory saturation.
- [x] Early-warning webhook notifications prior to kernel OOM invocation.
- [x] Interactive visual exhaustion meters on container overview cards.

---

## Milestone 12: v1.7.0 (Zero-Config LAN Peer Synchronization & Gossip Discovery)
- [x] UDP broadcast discovery for auto-detecting nearby dock-radar daemon nodes.
- [x] Gossip-based state exchange for multi-server cluster metrics.
- [x] Unified multi-host aggregated view in the embedded dashboard.

---

## Milestone 13: v1.8.0 (Zero-Downtime Rolling Restarts & Traffic Draining)
- [x] Staggered sequential container restarts with health check readiness probing.
- [x] Traffic draining and reverse proxy health status integration.
- [x] Configurable batch concurrency limit and rollback abort triggers.

---

## Milestone 14: v1.9.0 (Distributed Ephemeral Log Storage & S3 Offloader)
- [x] Compressed log chunking and local ring buffer rotation to disk.
- [x] Pure standard-library AWS SigV4 request signer with zero external dependencies.
- [x] Background asynchronous offloader streaming logs to S3-compatible object stores (MinIO, AWS S3, Cloudflare R2).
- [x] Ephemeral retention policies with capacity caps and offload-priority cold storage tiering.
- [x] Storage REST APIs, RBAC authorization, and Prometheus exporter metrics.
- [x] Glassmorphism chunk explorer, live KPI grid, download, and S3 configuration modal.

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

---

## Milestone 17: v2.2.0 (Container Image Vulnerability Scanner & SBOM Audit)
- [ ] In-line container image layer scanning and Common Vulnerabilities and Exposures (CVE) database lookup.
- [ ] Software Bill of Materials (SBOM) generation in SPDX and CycloneDX formats.
- [ ] Automated security severity grading and deployment gating triggers.

---

## Milestone 18: v2.3.0 (Distributed Rate-Limiting & Global Quota Orchestrator)
- [ ] Token bucket and sliding-window rate limiters synchronized across mesh peer nodes.
- [ ] Configurable per-tenant API quotas and bandwidth throttling controls.
- [ ] Distributed abuse mitigation with automatic IP ban propagation.

---

## Milestone 19: v2.4.0 (eBPF Micro-Firewall & Container Network Isolator)
- [ ] Kernel-level packet filtering and dynamic eBPF network isolation rules.
- [ ] Zero-trust network policy enforcement across inter-container traffic.
- [ ] Visual egress/ingress bandwidth inspector with automatic DDoS throttling.

---

## Milestone 20: v2.5.0 (GitOps Continuous Sync & Webhook Auto-Deployer)
- [ ] Automated git repository tracking with cryptographic commit signature verification.
- [ ] Zero-downtime container image pull and rollouts on verified webhook triggers.
- [ ] Automated rollback triggers with deployment health gating.

---

## Milestone 21: v2.6.0 (High-Availability Raft Cluster Consensus Engine)
- [ ] Embedded Raft consensus algorithm for distributed leader election across dock-radar coordinators.
- [ ] Replicated state machine synchronizing healing policies, container blacklist registers, and node states.
- [ ] Split-brain protection with automated cluster quorum reconciliation.

---

## Milestone 22: v2.7.0 (Zero-Trust WireGuard Mesh Tunneling & Peer Gateway)
- [ ] Userspace WireGuard encryption overlay for secure cross-cloud and edge-to-edge agent tunneling.
- [ ] Automatic cryptographic peer key exchange and dynamic IP address leasing.
- [ ] Low-overhead packet routing bypassing public firewall and NAT restrictions.

---

## Milestone 23: v2.8.0 (Autonomous Canary Deployment & Traffic Mirroring)
- [ ] Dynamic traffic percentage splitting with zero packet loss between container versions.
- [ ] Real-time error rate and latency divergence detection triggering automated rollback.
- [ ] Shadow traffic mirroring for risk-free pre-release performance profiling.

---

## Milestone 24: v2.9.0 (Distributed Core Dump & Crash Analysis Pipeline)
- [ ] Automatic container crash kernel core dump interception and ELF stack backtrace extraction.
- [ ] Symbolicated crash telemetry aggregation and root-cause classification.
- [ ] Crash signature deduplication and instant alert dispatch.

---

## Milestone 25: v3.0.0 (Self-Optimizing Query Cache & Event Ingestion Pipeline)
- [ ] In-memory adaptive query cache for high-frequency Prometheus scraping and telemetry feeds.
- [ ] Non-blocking Docker engine event multiplexer (`/events`) with dynamic backpressure regulation.
- [ ] Distributed event deduplication across mesh peers.

---

## Milestone 26: v3.1.0 (Zero-Knowledge Distributed Configuration Vault)
- [ ] End-to-end encrypted cluster secret sharing and synchronized configuration replication.
- [ ] Hardware-backed key derivation with automatic rotation and revocable cluster join tokens.
- [ ] Ephemeral secret leases with automated audit shredding.

---

## Milestone 27: v3.2.0 (Automated TLS ACME Let's Encrypt Certbot & Dynamic SNI)
- [ ] Automated ACME HTTP-01/DNS-01 challenge automation with Let's Encrypt and ZeroSSL.
- [ ] Dynamic SNI multiplexing routing multiple domain names over single 443 port.
- [ ] Ephemeral zero-downtime certificate rotation before expiration.

---

## Milestone 28: v3.3.0 (Zero-Copy Kernel BPF Ring Buffer Telemetry & Perf Profiler)
- [ ] Userspace zero-copy BPF ring buffer consumption reducing CPU overhead < 0.5%.
- [ ] Real-time kernel stack flame graph generator for active containers.
- [ ] Continuous on-CPU / off-CPU profiling telemetry exporter.

---

## Milestone 29: v3.4.0 (Adaptive Memory Compression & NUMA-Aware Container Balancer)
- [ ] Userspace zstandard/zstd chunk compression for cold container process memory pages.
- [ ] NUMA node topology discovery and CPU/RAM affinity pinning recommendations.
- [ ] Automatic memory pressure relief balancing across multi-socket NUMA domains.

---

## Milestone 30: v3.5.0 (Decentralized Cluster Event Log Streaming & P2P Gossip Relay)
- [ ] Gossip-propagated real-time event distribution tree with anti-entropy reconciliation.
- [ ] Dynamic peer relay routing minimizing inter-host WAN egress overhead.
- [ ] Ephemeral distributed search query broadcast with Merkle tree verification.


