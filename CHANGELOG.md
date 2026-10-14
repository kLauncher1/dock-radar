# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-10-14

### Added
- Interactive in-browser container terminal execution via bidirectional WebSocket (`/api/docker/exec`, `internal/api/exec.go`).
- Docker exec engine (`internal/docker/exec.go`) supporting dynamic exec instance creation, raw duplex socket hijacking (`Upgrade: tcp`), terminal dimension resizing, and status/exit inspection.
- High-fidelity VT100 / ANSI escape sequence renderer in the embedded web dashboard supporting 16 standard ANSI colors, 256-color palette (`\x1b[38;5;Nm`), font styles (bold, dim, italic, underline), line erase, and screen clears.
- Read-only shell access policy mode enforcing strict input blocking for read-only viewers or auditing scenarios, with visual policy watermark badges and toast alerts.
- Configurable idle session termination watchdog automatically closing inactive exec connections and reclaiming resources.
- Interactive terminal controls in web dashboard: target container selection, shell binary picker (`/bin/sh`, `/bin/bash`, `sh`, `/bin/ash`), read-only toggle, connection state indicators, and keyboard input capture (with Enter, Backspace, Tab, arrows, and Ctrl combinations).
- "Exec" action triggers in Container Radar table providing one-click terminal attachment to running containers.
- Comprehensive unit test suites in `internal/docker/exec_test.go` and `internal/api/exec_test.go` covering REST creation, RBAC authorization guards, connection hijacking, read-only policy enforcement, and stream message flow.

## [1.2.0] - 2026-10-14

### Added
- Multi-host agent mesh registry (`internal/mesh/node.go`) providing thread-safe remote node registration, node health tracking (`online`, `offline`, `degraded`, `unknown`), endpoint address sanitization, label tagging, and cluster-wide aggregate compute metrics calculation.
- Background concurrent health and telemetry prober (`internal/mesh/prober.go`) executing periodic non-blocking health checks, round-trip latency measurement, system metrics ingestion, and remote Docker container inventory synchronization with Bearer token authentication.
- Cluster mesh REST API endpoints (`internal/api/mesh.go`):
  - `GET /api/nodes` & `POST /api/nodes`: Node inventory listing and dynamic remote node registration with RoleAdmin authorization and audit logging.
  - `DELETE /api/nodes`: Remote node deregistration with audit trail recording.
  - `GET /api/cluster/summary`: Real-time aggregate telemetry (total/online/offline nodes, cluster-wide container counts, aggregate CPU percent, memory utilization).
  - `GET /api/cluster/containers`: Unified multi-node container aggregation with `node_id` and `state` filtering query parameters.
  - `POST /api/nodes/heartbeat`: Agent push endpoint allowing edge dock-radar instances to publish health telemetry and container status back to the coordinator.
- Prometheus exporter enhancement (`internal/metrics/prometheus.go`): Exposes cluster-wide node status gauges, probe latency metrics, total/running mesh container counts, and aggregate resource utilization across active mesh nodes.
- CLI flags and environment configuration: `--nodes` (`DOCK_RADAR_NODES`) for static bootstrap peer list, and `--node-name` (`DOCK_RADAR_NODE_NAME`) for custom node display names.
- Web dashboard enhancements (`web/dist/index.html`):
  - Header Cluster Mesh live badge showing aggregate online node count.
  - Sticky glassmorphism Cluster Summary bar displaying live cluster nodes, total/running containers, aggregate CPU, aggregate RAM, and node filter dropdown.
  - Interactive "Manage Nodes" modal panel with dynamic remote node registration form, active nodes table, probe latency, container counts, and one-click node unregistration.
  - Container Radar table augmented with node origin badges (`[node_name]`) and unified cluster view.

## [1.1.0] - 2026-10-14

### Added
- Standard Prometheus metrics exporter endpoint (`GET /metrics`, `internal/metrics/prometheus.go`) adhering to official exposition format (HELP, TYPE gauge/counter, label escaping) for host, container, ringbuffer, alert, and audit telemetry.
- Batch container operations engine (`internal/docker/batch.go`) providing synchronized multi-container lifecycle execution (`RestartAll`, `StopAll`) and automatic inactive container cleanup (`PruneContainers`) with Docker API prune endpoint negotiation and manual fallback.
- High-performance, thread-safe circular audit logger (`internal/audit/logger.go`) buffering up to 2,000 security and administrative actions with actor metadata, client IP tracking, and execution status.
- Audit trail streaming and export endpoint (`GET /api/audit/export`) delivering historical operational records in newline-delimited JSON (NDJSON) and JSON formats with action and limit filters.
- Batch container control API endpoint (`POST /api/docker/batch`) guarded by RoleAdmin authorization, token bucket rate limiting, and automated audit logging.
- Embedded web console additions: Prometheus `/metrics` navigation pill, one-click `Export Audit` NDJSON downloader, and interactive batch operation triggers ("Restart All", "Stop All", "Prune Inactive") with confirmation modals.

## [1.0.0] - 2026-10-14

### Added
- In-memory TLS certificate auto-generation engine (`internal/security/tls.go`) creating self-signed ECDSA P-256 X.509 certificates with Subject Alternative Names (SANs) for localhost, loopbacks, and network interfaces.
- Modern TLS configuration enforcing minimum TLS 1.2 with secure cipher suites (AES-GCM, ChaCha20-Poly1305) and curve preferences (X25519, P-256).
- Support for custom external certificate and private key file paths via `--tls-cert` and `--tls-key` CLI flags and environment variables.
- Bearer token authentication engine (`internal/security/auth.go`) implementing Role-Based Access Control (Admin vs Viewer).
- Constant-time token verification (`crypto/subtle.ConstantTimeCompare`) guarding against side-channel timing attacks.
- WebSocket log stream authentication support through URL query parameter token extraction (`?token=<token>`).
- Client authentication status and token verification endpoints (`GET /api/auth/status`, `POST /api/auth/verify`).
- Embedded web console Security & Authentication modal with localStorage token persistence, live connection telemetry, and role status indicators.
- Command-line flags and environment variable bindings (`--port`, `--tls`, `--tls-cert`, `--tls-key`, `--admin-token`, `--viewer-token`, `--allow-remote`, `--version`).
- Multi-platform cross-compilation matrix in GitHub Actions CI targeting Linux (amd64, arm64), macOS (amd64, arm64 Apple Silicon), and Windows (amd64).

## [0.4.0] - 2026-10-14

### Added
- Automated outgoing webhook alert engine (`internal/alert`) delivering instant notifications to Discord and Slack channels.
- Discord rich embed formatter with color-coded severity levels (Critical, Warning, Info) and structured metric fields.
- Slack attachment payload builder with color hex highlights and event source details.
- Background health failure monitor (`internal/alert/monitor.go`) tracking container state transitions and unexpected exits.
- Sliding window restart flapping detection identifying crash-looping containers with configurable threshold counts.
- Real-time host memory and CPU utilization threshold monitors with automated alert dispatch.
- Alert configuration management endpoints (`GET /api/alerts/config`, `POST /api/alerts/config`) with loopback origin validation and token bucket rate limits.
- Incident history endpoint (`GET /api/alerts/events`) and manual channel test trigger (`POST /api/alerts/test`).
- Web console "Alerts & Notifications" panel featuring webhook channel URLs, threshold adjustments, live test triggers, and recent incident event log feed.
- Comprehensive SSRF defense and control character sanitization protecting against metadata endpoints and CRLF injection.

## [0.3.0] - 2026-10-14

### Added
- Real-time container log streaming endpoint (`GET /api/docker/logs`) supporting both RFC 6455 WebSockets and REST JSON snapshots.
- Pure standard library RFC 6455 WebSocket upgrader and frame serializer with zero external dependencies.
- Docker engine log demultiplexing supporting 8-byte frame parsing (stdout vs stderr separation) and raw TTY streams.
- High-performance, thread-safe circular ring buffer (`internal/logs/ringbuffer.go`) keeping memory utilization under 15 MB.
- Embedded console real-time terminal widget with stream filter tabs (All, stdout, stderr, system), auto-scrolling, container selector, and live WebSocket connection indicator.
- Individual container "Logs" action button on container radar rows for instantaneous terminal targeting.

### Fixed
- Cross-platform HTTP base URL resolution ensuring consistent Docker socket communication across Linux and Windows environments.

## [0.2.0] - 2026-10-13

### Added
- Container lifecycle control endpoints (`POST /api/docker/restart`, `POST /api/docker/stop`) supporting JSON payloads and query fallback.
- Interactive action controls in embedded dashboard with confirmation modal dialogs and live execution feedback.
- Loopback origin enforcement and anti-CSRF request validation to restrict mutations to local clients.
- In-memory token bucket rate limiter to protect Docker engine sockets from rapid invocation churn.
- Strict container identifier validation regex and length limits preventing path traversal or parameter injection.
- Isolated test suites covering lifecycle actions, HTTP routing, security guards, and rate limit exhaustion.

## [0.1.0] - 2026-10-13

### Added
- Single-binary zero-dependency container monitor architecture using Go `//go:embed`.
- Low-overhead Docker socket client (`/var/run/docker.sock` and Windows Named Pipe) with resilient offline fallback.
- Host system telemetry collector for real-time CPU, RAM, goroutines, and GC stats.
- Dark-mode glassmorphism web console dashboard with real-time JSON polling endpoints (`/api/system`, `/api/docker`).
- Ultra-low memory footprint operating persistently under 15 MB of RAM.
- Comprehensive unit test suite with 100% test pass rate.
