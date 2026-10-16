# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.0] - 2026-10-16

### Added
- Distributed Ephemeral Log Storage & S3 Offloader Engine (`internal/storage/`):
  - Pure standard-library Gzip log chunker with cryptographic SHA-256 integrity verification and atomic temporary file disk writes (`internal/storage/chunker.go`, `internal/storage/chunker_test.go`).
  - Zero-dependency AWS Signature Version 4 (SigV4) request signer implementing HMAC-SHA256 canonical request, string-to-sign, and derived credential signing (`internal/storage/sigv4.go`, `internal/storage/sigv4_test.go`).
  - Native S3Client supporting AWS S3, MinIO, and Cloudflare R2 with automatic path-style vs virtual-host addressing, HeadBucket probing, and PutObject/DeleteObject operations (`internal/storage/s3_client.go`, `internal/storage/s3_client_test.go`).
  - Ephemeral local disk retention engine enforcing age expiration, max chunk counts, max disk byte quotas, and offload-priority pruning (`internal/storage/retention.go`, `internal/storage/retention_test.go`).
  - Asynchronous S3 offload worker queue with exponential backoff retries, status tracking, and graceful fallback when cloud storage is unconfigured (`internal/storage/offloader.go`, `internal/storage/offloader_test.go`).
  - Central StorageManager orchestrating in-memory ring buffer ingestion, scheduled chunk flushing, query indexing, and runtime config updates (`internal/storage/manager.go`, `internal/storage/manager_test.go`).
- Log Storage REST APIs (`internal/api/storage.go`, `internal/api/storage_test.go`):
  - `GET /api/logs/storage/status`: Returns chunk inventory, disk usage, queue depth, and S3 status (requires `RoleViewer`).
  - `GET /api/logs/storage/chunks`: Returns paginated and filtered chunk records (`?container=`, `?stream=`, `?s3_status=`, `?limit=`, `?offset=`).
  - `GET /api/logs/storage/chunk`: Retrieves individual chunk metadata, unpacked log entries (`?entries=true`), or downloads raw `.gz` archives (`?download=true`).
  - `POST /api/logs/storage/flush`: Immediately flushes active memory buffers to disk chunks and enqueues to S3 (requires `RoleAdmin`).
  - `GET /api/logs/storage/config`: Returns active retention rules and masked S3 credentials (requires `RoleViewer`).
  - `POST /api/logs/storage/config`: Updates S3 credentials and retention limits dynamically with validation (requires `RoleAdmin`).
  - `POST /api/logs/storage/test`: Probes S3 connectivity and bucket access on demand (requires `RoleAdmin`).
- Prometheus Metrics Exporter Extension (`internal/metrics/storage.go`, `internal/metrics/prometheus.go`):
  - Exposes `dock_radar_log_storage_chunks_total`, `dock_radar_log_storage_disk_bytes`, `dock_radar_log_storage_offloaded_total`, `dock_radar_log_storage_offload_failed_total`, `dock_radar_log_storage_queue_depth`, and `dock_radar_log_storage_s3_enabled` gauges for Grafana telemetry.
- Embedded Dark-Mode Dashboard Glassmorphism UI (`web/dist/index.html`):
  - Header Log Storage status pill (`💾 Log Storage: X Chunks (Y MB)`) with one-click settings launcher.
  - Storage & S3 Offloader card featuring summary KPI counters, S3 target state, and manual buffer flush action.
  - Interactive Chunk Explorer table with container/stream/status filtering, compression ratios, time spans, and direct `.gz` downloads.
  - Storage & S3 Configuration Modal (`#storage-modal`) with live S3 connection testing and credential management.
  - Chunk Metadata & Log Record Inspector Modal (`#chunk-details-modal`) displaying SHA-256 checksums, cloud keys, and unpacked log lines.
- Command-Line Flags & Environment Variables (`main.go`):
  - `--s3-endpoint`, `--s3-bucket`, `--s3-region`, `--s3-access-key`, `--s3-secret-key`, `--s3-prefix`, and `--log-storage-dir`.

## [1.8.0] - 2026-10-15

### Added
- Zero-Downtime Rolling Restarts & Traffic Draining Engine (`internal/rolling/engine.go`, `internal/rolling/types.go`):
  - Staggered sequential container restarts across replicas with configurable concurrency batch size (1 to 10).
  - Multi-strategy target resolution supporting specific container ID lists, Docker Compose stacks (`com.docker.compose.project`), and arbitrary label selectors (`key=val`).
  - Active execution tracking with cancellable context trees, manual abort triggers, and automatic progress timeline updates.
- Graceful Traffic Draining & Reverse Proxy Integration (`internal/rolling/drain.go`, `internal/rolling/drain_test.go`):
  - In-flight request evacuation with configurable countdown timeouts (0 to 300 seconds).
  - Outgoing HTTP webhook notifications dispatching drain and undrain signals to reverse proxies (Nginx, Traefik, Envoy, HAProxy) with container ID token substitution.
- Multi-Stage Container Readiness Prober (`internal/rolling/probe.go`, `internal/rolling/probe_test.go`):
  - Deep container inspection ensuring containers transition to running state and exit code 0.
  - Native Docker health check monitoring waiting for `(healthy)` and fast-aborting on `(unhealthy)`.
  - HTTP readiness probes querying configurable application endpoints (`/healthz`) on target ports.
  - Configurable post-readiness grace periods confirming container stability before advancing to subsequent batches.
- Automated Failure Abort & Rollback Mechanism (`internal/rolling/engine.go`, `internal/rolling/store.go`):
  - Instant halt of rolling pipeline upon reaching the failure threshold to safeguard healthy running replicas.
  - Automated rollback triggering container recovery and audit trail event generation.
  - High-priority alert notification dispatch to Discord and Slack webhook channels.
- Rolling Restart REST APIs (`internal/api/rolling.go`, `internal/api/rolling_test.go`):
  - `POST /api/rolling/start`: Launches a rolling restart operation with parameter validation (requires `RoleAdmin`).
  - `GET /api/rolling/status`: Returns current engine statistics and active operations in flight (requires `RoleViewer`).
  - `GET /api/rolling/operations`: Lists historical operations and provides detailed step timelines (`?id=`, `?limit=`).
  - `POST /api/rolling/abort`: Cancels an active rolling restart execution (requires `RoleAdmin`).
- Prometheus Metrics Exporter Extension (`internal/metrics/rolling.go`, `internal/metrics/prometheus.go`):
  - Exposes `dock_radar_rolling_operations_total`, `dock_radar_rolling_operations_active`, `dock_radar_rolling_containers_restarted_total`, `dock_radar_rolling_containers_failed_total`, and `dock_radar_rolling_rollbacks_total` metrics for Grafana dashboards.
- Embedded Dark-Mode Dashboard Glassmorphism UI (`web/dist/index.html`):
  - Zero-Downtime Rolling Restarts card with summary KPI counters and real-time execution progress bar.
  - Interactive launcher modal with strategy selector, batch size slider, drain timeout, HTTP probe settings, and auto-rollback toggle.
  - Active container step indicators (Pending ➔ Draining ➔ Restarting ➔ Probing ➔ Healthy).
  - Historical execution audit table with one-click manual abort triggers.

## [1.7.0] - 2026-10-15

### Added
- Dynamic LAN Auto-Discovery Engine (`internal/mesh/discovery.go`, `internal/mesh/discovery_test.go`):
  - Zero-configuration local network peer detection broadcasting periodic announcements over UDP port 9085.
  - Multi-interface broadcast traversal automatically reaching across all physical LAN adapters and link interfaces.
  - Strict packet bounds checking (capped to 1 KB datagrams) and cluster domain key isolation (`dock-radar-cluster`).
  - Automatic peer TTL expiration and state synchronization into the central node mesh registry.
- SWIM-Based Gossip Protocol Consensus Engine (`internal/mesh/gossip.go`, `internal/mesh/gossip_test.go`):
  - Distributed failure detection implementing Structured Weakly-consistent Infection-style Process Group Membership (SWIM).
  - Two-phase health probing: direct randomized peer pings with configurable timeouts (800ms) and indirect fallback pings via $k$-random helper nodes ($k=3$) to eliminate false network hiccup penalties.
  - Incarnation refutation protocol: nodes receiving suspicion updates concerning themselves automatically increment local incarnation counters and broadcast alive assertions to immediately refute transient network partitions.
  - State update precedence guarantees (`Dead > Suspect > Alive` within identical incarnation numbers; higher incarnation always supersedes lower).
  - Configurable suspicion timeout watchdogs transitioning unrefuted suspect nodes to dead status.
- Cluster Mesh Discovery & Gossip REST APIs (`internal/api/gossip.go`, `internal/api/gossip_test.go`):
  - `GET /api/mesh/discovery`: Returns auto-discovery listener status, broadcast port, cluster key, and detected LAN peers.
  - `POST /api/mesh/discovery`: Manually triggers an immediate broadcast announcement across all local network interfaces (requires `RoleAdmin`).
  - `GET /api/mesh/gossip`: Reports SWIM cluster health consensus, local incarnation, member states, and transmission counters.
  - `POST /api/mesh/gossip`: High-performance HTTP peer transport for exchanging SWIM protocol packets, membership state infection, and ACK handshakes.
- Prometheus Metrics Exporter Extension (`internal/metrics/prometheus.go`):
  - Exposes `dock_radar_mesh_discovery_enabled`, `dock_radar_mesh_discovery_peers_detected_total`, `dock_radar_mesh_discovery_beacons_sent_total`, `dock_radar_mesh_discovery_beacons_received_total`, `dock_radar_mesh_gossip_incarnation`, `dock_radar_mesh_gossip_members`, `dock_radar_mesh_gossip_messages_sent_total`, and `dock_radar_mesh_gossip_messages_received_total` gauges.
- Multi-Host Cross-Node Overview Dashboard (`web/dist/index.html`):
  - Real-time LAN auto-discovery status card with active UDP beacon indicator and immediate broadcast trigger button.
  - SWIM protocol consensus card displaying live member states (🟢 Alive, 🟡 Suspect, 🔴 Dead), incarnation counter, and round-trip ping latencies.
  - Interactive multi-host topology grid showing compute load (CPU/RAM) and container allocation per node with instant one-click node isolation filters.

## [1.6.0] - 2026-10-14

### Added
- Predictive Anomaly Detection Engine & Linear Regression Memory Trend Tracking (`internal/anomaly/regression.go`, `internal/anomaly/series.go`):
  - In-memory thread-safe circular metric buffer (`ContainerSeries`) sampling active container memory and CPU points up to configurable capacities with automatic eviction.
  - Robust Ordinary Least Squares (OLS) linear regression modeling time vs memory utilization with numerical stability guards against zero-variance divisions.
  - Mathematical calculation of consumption slope ($m$, bytes/sec), intercept ($c$), coefficient of determination ($R^2$), and dynamic Time-to-Exhaustion (TTE) prediction.
  - Multi-tier risk classification: `critical_oom_imminent` (exhaustion < 120s or usage > 92%), `warning` (exhaustion < 300s or growth rate > 10 MB/s), `moderate_growth`, and `stable`.
- Early-Warning OOM Alert System (`internal/anomaly/alarm.go`, `internal/anomaly/detector.go`):
  - Automated early warning alarm dispatch triggering before kernel OOM killer (`exit 137`) terminates containers.
  - Non-blocking webhook dispatch bridge into Discord and Slack notification channels via `alert.Dispatcher` with timeout-bounded context execution.
  - Incident event deduplication with configurable cooldown periods to prevent alert fatigue.
  - Thread-safe circular event buffer recording recent OOM warning occurrences with sub-millisecond retrieval.
- Anomaly & Predictive OOM REST APIs (`internal/api/anomaly.go`):
  - `GET /api/anomaly/predictions`: Returns current linear regression predictions and risk states for all containers or targeted container IDs (`?id=`), with optional `?filter=at_risk` query support.
  - `GET /api/anomaly/config`: Returns active anomaly detection thresholds, sampling interval, and alert window configurations (requires `RoleViewer`).
  - `POST /api/anomaly/config`: Atomically updates anomaly thresholds and alert settings, guarded by `RoleAdmin` RBAC authorization and rate limiting.
  - `GET /api/anomaly/events`: Returns bounded incident history of recent early-warning OOM triggers.
- Prometheus Metrics Exporter Extension (`internal/metrics/prometheus.go`):
  - Exposes `dock_radar_anomaly_containers_monitored`, `dock_radar_anomaly_critical_imminent_total`, `dock_radar_anomaly_warning_total`, `dock_radar_anomaly_memory_growth_rate_bytes_per_sec`, and `dock_radar_anomaly_predicted_oom_seconds` gauges for Grafana alerting.
- Docker Stats Telemetry Engine (`internal/docker/stats.go`):
  - Direct Docker socket `/stats?stream=false` inspection with effective memory calculation (deducting kernel reclaimable page caches `inactive_file`/`total_inactive_file` to match `docker stats` CLI fidelity).
  - Accurate CPU delta utilization percent computation across polling intervals.
- Embedded Dark-Mode Dashboard Glassmorphism UI (`web/dist/index.html`):
  - Real-time header badge indicator (`🔮 OOM Radar: Normal / Warning / Critical`) with click-to-open configuration modal.
  - Real-time `OOM Forecast` column in container overview table with glowing countdown badges (`🚨 OOM in 45s!`, `🟠 ~3m 20s`, `🟡 +X MB/s`, `🟢 Stable`).
  - Predictive Anomaly Radar & OOM Forecast Card with summary KPI grid and container trend forecasts table.
  - Predictive OOM Alarms Configuration Modal (`#anomaly-modal`) with threshold adjustment controls, webhook alert toggles, and incident history audit trail.
- Comprehensive Unit & Integration Test Suites:
  - Full test coverage in `internal/anomaly/regression_test.go`, `internal/anomaly/series_test.go`, `internal/anomaly/alarm_test.go`, `internal/anomaly/detector_test.go`, `internal/docker/stats_test.go`, and `internal/api/anomaly_test.go`.

## [1.5.0] - 2026-10-14

### Added
- Autonomous Self-Healing Container Policies & Remediation Engine (`internal/healing/engine.go`):
  - Autonomous failure detection and recovery engine executing automated restarts on Out-Of-Memory (OOM) killed containers (`Exited (137)`), flapping restart loops (`restarting`), and failed Docker health checks (`unhealthy`).
  - Thread-safe configuration repository (`internal/healing/policy.go`) with input sanitization, boundaries validation, and container exclusion filters (`dock-radar.healing=false` label and `excluded_containers` rules).
  - Exponential backoff with randomized cryptographic jitter (`internal/healing/jitter.go`) desynchronizing restart bursts to prevent daemon socket saturation and cascading failure thrashing.
  - Rollback protection & quarantine circuit breaker: tracks per-container remediation attempts, halting automated restarts and placing recurrently failing containers in quarantine once `max_attempts` is reached.
  - Bounded circular remediation audit trail buffer (`internal/healing/history.go`) capturing timestamped failure triggers, attempt counters, jitter delays, and execution outcomes with zero-allocation retrieval.
- Self-Healing REST APIs (`internal/api/healing.go`):
  - `GET /api/healing/config`: Returns active remediation rules and thresholds (requires `RoleViewer`).
  - `POST /api/healing/config`: Atomically updates self-healing policy configuration (requires `RoleAdmin` with rate limiting).
  - `GET /api/healing/status`: Real-time remediation KPIs, active backoffs, and list of quarantined containers.
  - `GET /api/healing/history`: Filterable remediation audit trail events (`?limit=`, `?container_id=`, `?trigger=`).
  - `POST /api/healing/reset`: Clears circuit breaker states for a specific container or all quarantined services.
- Prometheus Metrics Exporter Enhancement (`internal/metrics/prometheus.go`):
  - Exposes `dock_radar_healing_enabled`, `dock_radar_healing_remediations_total`, `dock_radar_healing_quarantined_containers`, and `dock_radar_healing_active_backoffs` gauges for observability dashboards.
- Embedded Dark-Mode Dashboard Additions (`web/dist/index.html`):
  - Header status pill indicator (`🛡️ Healing: Active` / `Quarantined`) with quick-action modal trigger.
  - Dedicated Self-Healing & Remediation section featuring real-time KPI overview cards, live remediation audit feed, and one-click circuit breaker reset triggers.
  - Interactive Self-Healing Policy configuration modal with input toggles and parameter tuning.
- Modularization Refactoring:
  - Extracted log streaming handlers to dedicated `internal/api/logs.go` module, streamlining `internal/api/handlers.go` to strictly adhere to the 300-500 line soft ceiling across all files.
- Comprehensive Unit Test Suites:
  - Added full test coverage across `internal/healing/policy_test.go`, `internal/healing/jitter_test.go`, `internal/healing/history_test.go`, `internal/healing/engine_test.go`, `internal/api/healing_test.go`, and `internal/metrics/prometheus_test.go`.

## [1.4.0] - 2026-10-14

### Added
- Docker Compose topology engine (`internal/docker/compose.go`) auto-grouping active containers by `com.docker.compose.project` labels and synthesizing multi-tier dependency graphs.
- Robust parsing and normalization of `com.docker.compose.depends_on` labels supporting JSON dictionaries, comma-separated service lists, and conditional specifications (`service_healthy`, `service_started`).
- Architectural tier classifier (`DetectServiceRole`) categorizing containers into database, cache, message queue, web gateway, worker, storage, or generic service roles based on image names and service labels.
- Automated topology graph generator (`BuildTopologyGraph`) mapping services into topological layers with coordinate computation, directed dependency edges, and cross-tier inference.
- Whole-stack lifecycle management (`RestartStack`, `StopStack`, `RecreateStack`) executing synchronized container restart, graceful termination, and service recreation in dependency sequence.
- Docker Compose REST endpoints (`internal/api/compose.go`):
  - `GET /api/docker/compose`: Lists active Compose stacks, service inventories, dependency topologies, and stack health summaries (`healthy`, `degraded`, `stopped`, `empty`) with optional `?project=` filter.
  - `POST /api/docker/compose/action`: Triggers synchronized `restart`, `stop`, or `recreate` operations across all containers in a stack, guarded by `RoleAdmin` RBAC authorization and token bucket rate limits.
- Audit trail event logging for Compose stack lifecycle events (`compose_stack_restart`, `compose_stack_stop`, `compose_stack_recreate`) recording affected container counts and execution outcomes.
- Prometheus exporter enhancement (`internal/metrics/prometheus.go`): Exposes `dock_radar_compose_stacks_total` and `dock_radar_compose_stack_services{health="...",project="...",state="running|total"}` gauges for Grafana monitoring.
- Interactive Glassmorphism Compose Topology Canvas & Stack Inspector in embedded web dashboard (`web/dist/index.html`):
  - Stack selection tab pills with real-time health indicators and stack counter pill.
  - Interactive SVG dependency topology canvas rendering glowing service nodes, role icons, and directional bezier flow links.
  - Whole-stack lifecycle action toolbar ("Restart Stack", "Stop Stack", "Recreate Stack") with modal confirmation prompts and feedback toasts.
  - Comprehensive Compose services table listing project names, service tiers, container IDs, images, dependencies, and quick control triggers.
- Comprehensive unit test suites in `internal/docker/compose_test.go`, `internal/api/compose_test.go`, and `internal/metrics/prometheus_test.go`.

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
