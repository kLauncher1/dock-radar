# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.7.0] - 2026-10-31

### Added
- Zero-Trust WireGuard Mesh Tunneling & Peer Gateway (`internal/wireguard/`):
  - Pure standard-library userspace WireGuard overlay protocol engine with RFC 7748 Curve25519 (X25519) Diffie-Hellman key exchange (`crypto/ecdh`) and symmetric AEAD encryption (`internal/wireguard/crypto.go`, `internal/wireguard/crypto_test.go`).
  - Dynamic overlay IP address leasing (`IPPool`) managing virtual CIDR subnets with collision detection, address reclamation, and DHCP-like address pool allocation (`internal/wireguard/ippool.go`, `internal/wireguard/ippool_test.go`).
  - Zero-trust cryptokey routing table (`Router`) validating packet source IPs against peer AllowedIPs prefixes and performing dynamic NAT hole punching with endpoint roaming (`internal/wireguard/router.go`, `internal/wireguard/router_test.go`).
  - Central `Engine` orchestrating peer provisioning, cryptographic handshake initiation/response, 64-packet bitmap anti-replay window protection, packet routing, and background lease reclamation (`internal/wireguard/engine.go`, `internal/wireguard/engine_test.go`).
  - Core domain data models, configuration validator, and key masking (`internal/wireguard/types.go`, `internal/wireguard/types_test.go`).
- WireGuard REST APIs (`internal/api/wireguard.go`, `internal/api/wireguard_test.go`):
  - `GET /api/wireguard/status`: Queries WireGuard tunnel status, virtual IP, active peers, and telemetry (requires `RoleViewer`).
  - `GET /api/wireguard/peers`: Lists registered mesh peers with public keys, endpoints, and traffic metrics (requires `RoleViewer`).
  - `POST /api/wireguard/peers`: Provisions a new mesh peer or updates existing peer configuration (requires `RoleAdmin`).
  - `DELETE /api/wireguard/peers`: Removes a mesh peer and frees its IP lease (requires `RoleAdmin`).
  - `POST /api/wireguard/handshake`: Manually initiates cryptographic re-keying handshake with a peer (requires `RoleAdmin`).
  - `GET /api/wireguard/leases`: Lists dynamic overlay IP leases (requires `RoleViewer`).
  - `POST /api/wireguard/leases/reclaim`: Reclaims expired dynamic IP leases (requires `RoleAdmin`).
  - `GET /api/wireguard/routes`: Queries userspace routing table entries (requires `RoleViewer`).
  - `POST /api/wireguard/keygen`: Generates fresh X25519 keypair and symmetric preshared key (requires `RoleAdmin`).
  - `GET /api/wireguard/config`: Retrieves gateway configuration with masked private key (requires `RoleViewer`).
- Prometheus Metrics Exporter Extension (`internal/metrics/wireguard.go`, `internal/metrics/prometheus.go`):
  - Exposes `dock_radar_wireguard_enabled`, `dock_radar_wireguard_listen_port`, `dock_radar_wireguard_peers_count`, `dock_radar_wireguard_peers_connected`, `dock_radar_wireguard_rx_bytes_total`, `dock_radar_wireguard_tx_bytes_total`, `dock_radar_wireguard_active_leases`, and `dock_radar_wireguard_routing_rules_count`.
- Embedded Glassmorphism Web Console (`web/dist/index.html`):
  - Header WireGuard status badge (`#wireguard-badge`) displaying connected peer count with direct modal launch.
  - Zero-Trust WireGuard Mesh Tunneling dashboard section with 6 live KPI cards (Tunnel Gateway, Virtual Subnet & IP, Mesh Peers, Dynamic IP Leases, Encrypted RX, Encrypted TX).
  - Interactive tabs for Mesh Peers, Dynamic Overlay IP Pool, and Zero-Trust Routing & NAT Topology.
  - Interactive WireGuard Modal (`#wireguard-modal`) featuring Provision Mesh Peer form, X25519 Keypair Generator, and Tunnel Diagnostics.
- Command-Line Flags & Environment Variables (`main.go`):
  - Added `--wireguard`, `--wireguard-port`, `--wireguard-cidr`, and `--wireguard-keepalive` flags with environment variable bindings (`DOCK_RADAR_WIREGUARD_ENABLED`, `DOCK_RADAR_WIREGUARD_PORT`, `DOCK_RADAR_WIREGUARD_CIDR`, `DOCK_RADAR_WIREGUARD_KEEPALIVE`).

## [2.6.0] - 2026-10-30

### Added
- High-Availability Raft Cluster Consensus Engine (`internal/raft/`):
  - Pure standard-library Raft consensus algorithm implementation with zero external runtime dependencies (`internal/raft/engine.go`, `internal/raft/handlers.go`, `internal/raft/engine_test.go`).
  - Randomized election timeout jitter and automated leader election maintaining authority through periodic heartbeats.
  - Strict majority quorum validation (`(N/2) + 1`) providing split-brain immunity across network partitions.
  - In-memory replicated log storage with monotonic 1-based indexing, conflict suffix truncation, and checkpoint compaction (`internal/raft/log.go`, `internal/raft/log_test.go`).
  - Replicated State Machine (`StateMachine`) synchronizing autonomous self-healing policies, container quarantine blacklists, cluster node states, and dynamic cluster key-values (`internal/raft/fsm.go`, `internal/raft/fsm_test.go`).
  - Resilient inter-node HTTP transport with bounded timeouts, URL validation, and optional Bearer token authentication (`internal/raft/transport.go`, `internal/raft/transport_test.go`).
  - Core domain data models, configuration validator, and node ID bounds checking (`internal/raft/types.go`, `internal/raft/types_test.go`).
- Raft Consensus REST APIs (`internal/api/raft.go`, `internal/api/raft_test.go`):
  - `GET /api/raft/status`: Retrieves consensus status, term, node role, leader ID, commit index, and quorum (requires `RoleViewer`).
  - `GET /api/raft/fsm`: Queries synchronized state machine data including healing policy, blacklist, and node directory (requires `RoleViewer`).
  - `POST /api/raft/propose`: Submits state mutations to cluster leader for log replication and quorum commit (requires `RoleAdmin`).
  - `GET /api/raft/peers`: Lists active consensus peers and quorum size (requires `RoleViewer`).
  - `POST /api/raft/peers`: Dynamically registers a new peer node into the consensus group (requires `RoleAdmin`).
  - `DELETE /api/raft/peers`: Removes a peer node from the consensus group (requires `RoleAdmin`).
  - `POST /api/raft/stepdown`: Forces leader to step down to follower for automated failover drills (requires `RoleAdmin`).
  - `POST /api/raft/snapshot`: Triggers on-demand state machine snapshot and log compaction (requires `RoleAdmin`).
  - `POST /api/raft/rpc/vote`: Internal Raft RPC handling candidate vote solicitations.
  - `POST /api/raft/rpc/append`: Internal Raft RPC handling log replication and heartbeats.
- Prometheus Metrics Exporter Extension (`internal/metrics/raft.go`, `internal/metrics/prometheus.go`):
  - Exposes `dock_radar_raft_is_leader`, `dock_radar_raft_term`, `dock_radar_raft_commit_index`, `dock_radar_raft_applied_index`, `dock_radar_raft_last_log_index`, `dock_radar_raft_peers_count`, `dock_radar_raft_quorum_size`, `dock_radar_raft_fsm_applied_total`, and `dock_radar_raft_state`.
- Embedded Glassmorphism Web Console (`web/dist/index.html`):
  - Header Raft status badge (`#raft-badge`) displaying role and term with direct modal launch.
  - High-Availability Raft Cluster Consensus Engine dashboard section with 6 live KPI cards (Consensus Role, Term & Leader, Commit Index, Active Quorum, FSM Blacklist, FSM Applied Total).
  - Interactive tabs for Consensus Topology & Peers, Replicated State Machine, and Split-Brain & Safety Architecture.
  - Interactive Raft Modal (`#raft-modal`) with Command Proposer, Cluster Peers manager, and Failover/Compaction Drills.
- Command-Line Flags & Environment Variables (`main.go`):
  - Added `--raft`, `--raft-peers`, `--raft-heartbeat`, `--raft-election-timeout`, and `--raft-data-dir` flags with environment variable bindings (`DOCK_RADAR_RAFT_ENABLED`, `DOCK_RADAR_RAFT_PEERS`, `DOCK_RADAR_RAFT_HEARTBEAT`, `DOCK_RADAR_RAFT_ELECTION_TIMEOUT`, `DOCK_RADAR_RAFT_DATA_DIR`).

## [2.5.0] - 2026-10-30

### Added
- GitOps Continuous Sync & Webhook Auto-Deployer (`internal/gitops/`):
  - Automated Git repository tracking and branch polling over HTTP/HTTPS with smart refs parsing (`internal/gitops/tracker.go`, `internal/gitops/tracker_test.go`).
  - Cryptographic commit signature verification supporting GPG and SSH signatures, configurable signature policy enforcement (`disabled`, `warn`, `strict`), and authorized key ID validation (`internal/gitops/signature.go`, `internal/gitops/signature_test.go`).
  - Constant-time HMAC-SHA256 signature and GitLab token webhook authenticators defending against timing side-channel attacks.
  - Zero-downtime container image pull, container recreation rollout executor, and automated rollback engine with post-deployment HTTP health-check gating (`internal/gitops/deployer.go`, `internal/gitops/deployer_test.go`).
  - Central `Engine` orchestrating background repo polling, deployment rollouts, circular deployment audit history, webhook event dispatches (`alert.Event`), and structured audit logging (`audit.AuditEvent`) (`internal/gitops/engine.go`, `internal/gitops/engine_test.go`).
  - Core domain data models, repository configuration validator, and secret masking (`internal/gitops/types.go`, `internal/gitops/types_test.go`).
- GitOps REST APIs (`internal/api/gitops.go`, `internal/api/gitops_test.go`):
  - `GET /api/gitops/status`: Overall GitOps engine status, tracked repo counts, and rollout counters (requires `RoleViewer`).
  - `GET /api/gitops/repos`: Lists all tracked Git repositories with latest commit SHA and synchronization statuses (requires `RoleViewer`).
  - `POST /api/gitops/repos`: Registers a new Git repository or updates existing repository configuration (requires `RoleAdmin`).
  - `DELETE /api/gitops/repos`: Deregisters a tracked repository (requires `RoleAdmin`).
  - `POST /api/gitops/sync`: Manually triggers branch update check and sync (requires `RoleAdmin`).
  - `POST /api/gitops/deploy`: Manually triggers deployment rollout for a commit SHA (requires `RoleAdmin`).
  - `POST /api/gitops/rollback`: Executes rollback to previous commit and image tag (requires `RoleAdmin`).
  - `GET /api/gitops/deployments`: Queries recent deployment rollout records and logs (requires `RoleViewer`).
  - `POST /api/gitops/webhook`: Receives incoming GitHub (`X-Hub-Signature-256`) and GitLab (`X-Gitlab-Token`) push webhooks with HMAC validation.
  - `GET /api/gitops/config`: Retrieves global GitOps configuration with masked secrets (requires `RoleViewer`).
  - `POST /api/gitops/config`: Updates global GitOps engine configuration (requires `RoleAdmin`).
- Prometheus Metrics Exporter Extension (`internal/metrics/gitops.go`, `internal/metrics/prometheus.go`):
  - Exposes `dock_radar_gitops_active`, `dock_radar_gitops_tracked_repos`, `dock_radar_gitops_deployments_total`, `dock_radar_gitops_deployments_successful_total`, `dock_radar_gitops_deployments_failed_total`, `dock_radar_gitops_deployments_rolled_back_total`, and `dock_radar_gitops_strict_signatures_mode`.
- Embedded Glassmorphism Web Console (`web/dist/index.html`):
  - Header GitOps status badge (`#gitops-badge`) displaying tracked repo count with one-click modal launch.
  - Dedicated GitOps Continuous Sync & Webhook Auto-Deployer dashboard section with 5 live KPI cards (Tracked Repos, Total Rollouts, Success Rate, Auto Rollbacks, Engine Status).
  - Interactive tabs for Tracked Repositories and Rollout History with live status pills, manual sync, and rollback triggers.
  - Interactive GitOps Modal (`#gitops-modal`) with Repository Builder, Instant Rollout trigger, and Subsystem Configuration tabs.
- Command-Line Flags & Environment Variables (`main.go`):
  - Added `--gitops`, `--gitops-poll-interval`, `--gitops-strict-signatures`, `--gitops-auto-rollback`, and `--gitops-webhook-secret` flags with environment variable bindings (`DOCK_RADAR_GITOPS_ENABLED`, `DOCK_RADAR_GITOPS_POLL_INTERVAL`, `DOCK_RADAR_GITOPS_STRICT_SIGNATURES`, `DOCK_RADAR_GITOPS_AUTO_ROLLBACK`, `DOCK_RADAR_GITOPS_WEBHOOK_SECRET`).

## [2.4.0] - 2026-10-19

### Added
- eBPF Micro-Firewall & Container Network Isolator (`internal/firewall/`):
  - High-throughput packet evaluation pipeline supporting priority-ordered filtering rules with CIDR matching, port lists, transport protocols (TCP, UDP, ICMP), traffic directions (INGRESS, EGRESS, BOTH), and actions (ALLOW, DROP, REJECT, LOG) (`internal/firewall/filter.go`, `internal/firewall/filter_test.go`).
  - Zero-trust container network isolator enforcing strict inter-container network boundaries, quarantine state machines, granular peer whitelisting, and dropped packet telemetry counters (`internal/firewall/isolator.go`, `internal/firewall/isolator_test.go`).
  - Real-time bandwidth throughput inspector and volumetric DDoS detection engine calculating ingress/egress BPS and PPS deltas, sliding-window rate tracking, and automated alert triggering with deduplication (`internal/firewall/throttler.go`, `internal/firewall/throttler_test.go`).
  - Central `Engine` orchestrator coordinating packet filtering, container quarantine, bandwidth sampling, background container lifecycle reconciliation, webhook alerts, and structured audit logs (`internal/firewall/engine.go`, `internal/firewall/engine_test.go`).
  - Core domain models, configuration sanitization, and CIDR/port parsing helpers (`internal/firewall/types.go`, `internal/firewall/types_test.go`).
- eBPF Micro-Firewall REST APIs (`internal/api/firewall.go`, `internal/api/firewall_test.go`):
  - `GET /api/firewall/status`: Overall firewall engine status, active rule count, isolated containers, and packet evaluation counters (requires `RoleViewer`).
  - `GET /api/firewall/rules`: Lists active packet filtering rules with hit counters (requires `RoleViewer`).
  - `POST /api/firewall/rules`: Deploys a new filtering rule with priority ordering and CIDR validation (requires `RoleAdmin`).
  - `DELETE /api/firewall/rules`: Removes a filtering rule by ID (requires `RoleAdmin`).
  - `GET /api/firewall/isolation`: Lists container isolation and quarantine states with dropped counters (requires `RoleViewer`).
  - `POST /api/firewall/isolation`: Enforces zero-trust quarantine on a target container with peer allowlists (requires `RoleAdmin`).
  - `POST /api/firewall/isolation/unisolate`: Restores a quarantined container to nominal cluster network fabric (requires `RoleAdmin`).
  - `GET /api/firewall/bandwidth`: Container ingress and egress bandwidth rates (BPS/PPS) and peak utilization metrics (requires `RoleViewer`).
  - `GET /api/firewall/ddos/alerts`: Volumetric flood detection history and incident telemetry (requires `RoleViewer`).
  - `POST /api/firewall/simulate`: Performs synthetic packet evaluation through the filtering engine with nanosecond latency (requires `RoleAdmin`).
  - `GET /api/firewall/config`: Retrieves firewall engine configuration (requires `RoleViewer`).
  - `POST /api/firewall/config`: Updates firewall configuration, DDoS thresholds, and zero-trust policies (requires `RoleAdmin`).
- Prometheus Metrics Exporter Extension (`internal/metrics/firewall.go`, `internal/metrics/prometheus.go`):
  - Exposes `dock_radar_firewall_rules_active`, `dock_radar_firewall_containers_isolated`, `dock_radar_firewall_packets_permitted_total`, `dock_radar_firewall_packets_dropped_total`, `dock_radar_firewall_bytes_evaluated_total`, `dock_radar_firewall_ddos_events_total`, `dock_radar_firewall_active`, and `dock_radar_firewall_zerotrust_mode` metrics for Prometheus and Grafana dashboards.
- Embedded Glassmorphism Web Console (`web/dist/index.html`):
  - Header firewall status pill (`#firewall-badge`) displaying active rule count with direct modal launch.
  - Dedicated Micro-Firewall & Network Isolator dashboard section with 6 live KPI cards (Active Rules, Isolated Containers, Permitted Packets, Blocked/Dropped Packets, Evaluated Data, DDoS Events).
  - Four interactive tabs: Active Filter Rules, Zero-Trust Isolation Matrix, Bandwidth & Rate Monitor, and DDoS Defense Telemetry.
  - Interactive Firewall Management Modal (`#firewall-modal`) with Rule Builder, Container Quarantine, Packet Simulator, and Engine Settings.
- Command-Line Flags & Environment Variables (`main.go`):
  - Added `--firewall`, `--firewall-zerotrust`, `--firewall-ddos-pps`, `--firewall-ddos-bps`, and `--firewall-autoban` CLI flags with matching environment variables (`DOCK_RADAR_FIREWALL`, `DOCK_RADAR_FIREWALL_ZEROTRUST`, `DOCK_RADAR_FIREWALL_DDOS_PPS`, `DOCK_RADAR_FIREWALL_DDOS_BPS`, `DOCK_RADAR_FIREWALL_AUTOBAN`).

## [2.3.0] - 2026-10-18

### Added
- Distributed Rate-Limiting & Global Quota Orchestrator (`internal/ratelimit/`):
  - High-performance token bucket rate limiter supporting fractional token refill intervals and configurable burst capacities (`internal/ratelimit/token_bucket.go`, `internal/ratelimit/token_bucket_test.go`).
  - Sub-bucket sliding window rate limiter and bandwidth throttling controls calculating real-time consumption against rolling time windows (`internal/ratelimit/sliding_window.go`, `internal/ratelimit/sliding_window_test.go`).
  - Automated abuse tracking and IP banning engine (`IPBanTracker`) featuring violation thresholds, manual ban and unban mutations, local loopback immunity, and periodic background expiration sweeping (`internal/ratelimit/ip_ban.go`, `internal/ratelimit/ip_ban_test.go`).
  - Cross-node peer synchronization engine (`PeerSyncManager`) transmitting signed rate-limit updates and ban propagation events using HMAC-SHA256 signatures with 60-second replay attack defense (`internal/ratelimit/mesh_sync.go`, `internal/ratelimit/mesh_sync_test.go`).
  - Central `LimiterEngine` coordinating token buckets, per-tenant quotas, IP bans, audit logging (`audit.AuditEvent`), and webhook alert dispatches (`alert.Event`) (`internal/ratelimit/engine.go`, `internal/ratelimit/engine_test.go`).
  - Core domain models, configuration sanitization with secret masking, and identifier regex validation (`internal/ratelimit/types.go`, `internal/ratelimit/types_test.go`).
- Distributed Rate-Limiting & Quota REST APIs (`internal/api/ratelimit.go`, `internal/api/ratelimit_test.go`):
  - `GET /api/ratelimit/status`: Overall limiter engine status, tenant count, active bans, and sync metrics (requires `RoleViewer`).
  - `GET /api/ratelimit/tenants`: Lists all tenant quota definitions and real-time usage (requires `RoleViewer`).
  - `POST /api/ratelimit/tenants`: Configures or updates tenant RPS, burst limits, and bandwidth throttles (requires `RoleAdmin`).
  - `DELETE /api/ratelimit/tenants`: Removes a tenant quota definition (requires `RoleAdmin`).
  - `GET /api/ratelimit/bans`: Lists active IP ban records with expiration times and violation reasons (requires `RoleViewer`).
  - `POST /api/ratelimit/bans`: Manually bans an IP address or subnet (requires `RoleAdmin`).
  - `DELETE /api/ratelimit/bans`: Unbans an IP address (requires `RoleAdmin`).
  - `POST /api/ratelimit/sync`: Ingests and applies signed rate-limit and ban sync packets from peer nodes (requires `RoleAdmin` or valid HMAC signature).
  - `GET /api/ratelimit/config`: Returns limiter engine configuration with masked sync secrets (requires `RoleViewer`).
  - `POST /api/ratelimit/config`: Updates engine settings dynamically with parameter bounds validation (requires `RoleAdmin`).
- Prometheus Metrics Exporter Extension (`internal/metrics/ratelimit.go`, `internal/metrics/prometheus.go`):
  - Exposes `dock_radar_ratelimit_requests_total`, `dock_radar_ratelimit_rejected_total`, `dock_radar_ratelimit_bytes_total`, `dock_radar_ratelimit_active_bans`, `dock_radar_ratelimit_peer_sync_total`, and `dock_radar_ratelimit_active` metrics for Grafana monitoring.
- Embedded Dark-Mode Dashboard Glassmorphism UI (`web/dist/index.html`):
  - Header rate-limiting status badge (`#ratelimit-badge`) showing active quotas and bans with direct link to management modal.
  - Dedicated Distributed Rate-Limiting & Global Quota section with 6 live KPI counters (Total Requests, Rejected/Throttled, Active IP Bans, Configured Tenants, Synced Peers, Engine Status).
  - Interactive Tenant Quotas and IP Bans tables with dynamic add/remove triggers.
  - Rate-Limiting Management Modal (`#ratelimit-modal`) featuring 3 interactive tabs: Tenant Quotas, IP Ban List, and Mesh Sync & Config.
- Command-Line Flags & Environment Variables (`main.go`):
  - Added `--ratelimit`, `--ratelimit-default-rps`, `--ratelimit-burst`, `--ratelimit-autoban`, and `--ratelimit-sync-secret` with matching environment variable bindings (`DOCK_RADAR_RATELIMIT`, `DOCK_RADAR_RATELIMIT_DEFAULT_RPS`, `DOCK_RADAR_RATELIMIT_BURST`, `DOCK_RADAR_RATELIMIT_AUTOBAN`, `DOCK_RADAR_RATELIMIT_SYNC_SECRET`).

## [2.2.0] - 2026-10-18

### Added
- Container Image Vulnerability Scanner & SBOM Audit Engine (`internal/scanner/`):
  - In-line container image layer analysis and curated multi-ecosystem vulnerability database (`CVEDatabase`) covering Alpine (`apk`), Debian (`deb`), Go, NPM, and PyPI packages with semantic component-wise version comparison (`internal/scanner/cve_db.go`, `internal/scanner/cve_db_test.go`).
  - Spec-compliant Software Bill of Materials (SBOM) generator supporting both SPDX 2.3 and CycloneDX 1.5 JSON standards with package URL (pURL) formatting, license identification, and dependency relationship graphs (`internal/scanner/sbom.go`, `internal/scanner/sbom_test.go`).
  - Automated deployment security gating policy evaluator (`EvaluateGating`) with configurable maximum critical/high severity thresholds, `FailOnSeverity` triggers, CVE allowlists, and software license compliance policies (`internal/scanner/gating.go`, `internal/scanner/gating_test.go`).
  - Master Scanner Engine orchestrating periodic background sweeps, on-demand target scanning, in-memory TTL caching, ring-buffered scan reports, webhook alert dispatching, and audit logging (`internal/scanner/engine.go`, `internal/scanner/engine_test.go`).
- Container Vulnerability Scanner & SBOM REST APIs (`internal/api/scanner.go`, `internal/api/scanner_test.go`):
  - `GET /api/scanner/status`: Returns overall vulnerability scanner engine status, scan counts, and gating failure metrics (requires `RoleViewer`).
  - `GET /api/scanner/reports`: Lists recent container image vulnerability scan reports with container ID, image, and limit filters (requires `RoleViewer`).
  - `GET /api/scanner/report`: Retrieves detailed vulnerability report for a specific container ID or image name (requires `RoleViewer`).
  - `POST /api/scanner/scan`: Initiates on-demand vulnerability scan for a container image or triggers a full cluster container sweep (requires `RoleAdmin`).
  - `GET /api/scanner/sbom`: Generates and exports downloadable SPDX 2.3 or CycloneDX 1.5 JSON SBOM documents with attachment headers (requires `RoleViewer`).
  - `GET /api/scanner/gating`: Retrieves current automated deployment gating policies and thresholds (requires `RoleViewer`).
  - `POST /api/scanner/gating`: Updates deployment gating policies and threshold rules dynamically (requires `RoleAdmin`).
- Prometheus Metrics Exporter Extension (`internal/metrics/scanner.go`, `internal/metrics/prometheus.go`):
  - Exposes `dock_radar_scanner_scans_total`, `dock_radar_scanner_vulnerabilities_total`, `dock_radar_scanner_critical_total`, `dock_radar_scanner_high_total`, `dock_radar_scanner_gating_passed_total`, `dock_radar_scanner_gating_failed_total`, and `dock_radar_scanner_active` gauges and counters for Grafana monitoring.
- Embedded Dark-Mode Dashboard Glassmorphism UI (`web/dist/index.html`):
  - Header scanner status badge (`🛡️ Scanner: X Audited`) with direct link to scanner management modal.
  - Dedicated Container Image Vulnerability Scanner & SBOM Audit section with 5 live KPI counters (Scanned Images, Critical CVEs, High Severity, Gating Passed, Gating Blocked).
  - Live vulnerability scan report table displaying container names, images, risk scores, package counts, CVE breakdown pills, gating status badges, and action triggers (View SBOM, Re-scan).
  - Scanner Management Modal (`#scanner-modal`) featuring 3 interactive tabs: On-Demand Scan Runner, Deployment Gating Policy Manager, and Live SPDX 2.3 / CycloneDX 1.5 SBOM JSON Viewer with download functionality.
- Command-Line Flags & Environment Variables (`main.go`):
  - Added `--scanner`, `--scanner-auto-scan`, `--scanner-interval`, and `--scanner-gating-severity` with matching environment variable bindings (`DOCK_RADAR_SCANNER`, `DOCK_RADAR_SCANNER_AUTO_SCAN`, `DOCK_RADAR_SCANNER_INTERVAL`, `DOCK_RADAR_SCANNER_GATING_SEVERITY`).

## [2.1.0] - 2026-10-17

### Added
- Multi-Region Edge Peer Federation & WAN Sync Engine (`internal/federation/`):
  - Authenticated encrypted overlay tunnels using AES-256-GCM cipher with HMAC-SHA256 signature verification and a 60-second replay-prevention window for zero-trust cross-region communication (`internal/federation/tunnel.go`, `internal/federation/tunnel_test.go`).
  - Low-bandwidth delta synchronization protocol computing deterministic SHA-256 container inventory digests, transmitting gzip-compressed JSON payloads across high-latency WAN links, and tracking bandwidth savings telemetry (`internal/federation/sync.go`, `internal/federation/sync_test.go`).
  - Geo-distributed container inventory routing with spherical Haversine distance calculations, weighted latency metrics, consecutive probe failure threshold triggers, probation recovery timers, and manual failover drills (`internal/federation/router.go`, `internal/federation/router_test.go`).
  - Master Federation Engine orchestrating background WAN probes, scheduled delta sync loops, container inventory reconciliation, and alert event dispatches (`internal/federation/engine.go`, `internal/federation/engine_test.go`).
- Federation & WAN Sync REST APIs (`internal/api/federation.go`, `internal/api/federation_test.go`):
  - `GET /api/federation/status`: Returns local region info, peer counts, and WAN synchronization status (requires `RoleViewer`).
  - `GET /api/federation/regions`: Lists all registered edge peer regions with latency and health metrics (requires `RoleViewer`).
  - `POST /api/federation/regions`: Registers or updates an edge peer region endpoint (requires `RoleAdmin`).
  - `DELETE /api/federation/regions`: Deregisters an edge peer region by ID (requires `RoleAdmin`).
  - `POST /api/federation/sync`: Ingests and processes WAN delta sync payloads between regions (requires `RoleAdmin` or valid tunnel signature).
  - `GET /api/federation/routes`: Resolves optimal geo-routing paths for container workloads across regions (requires `RoleViewer`).
  - `POST /api/federation/failover`: Triggers manual or simulated failover drills across edge regions (requires `RoleAdmin`).
  - `GET /api/federation/config`: Retrieves federation settings with masked tunnel keys (requires `RoleViewer`).
  - `POST /api/federation/config`: Updates federation settings dynamically with parameter validation (requires `RoleAdmin`).
- Prometheus Metrics Exporter Extension (`internal/metrics/federation.go`, `internal/metrics/prometheus.go`):
  - Exposes `dock_radar_federation_regions_total`, `dock_radar_federation_regions_healthy`, `dock_radar_federation_sync_success_total`, `dock_radar_federation_sync_fail_total`, `dock_radar_federation_wan_latency_ms`, and `dock_radar_federation_routes_total` gauges and counters for Grafana monitoring.
- Embedded Dark-Mode Dashboard Glassmorphism UI (`web/dist/index.html`):
  - Header federation status badge (`🌐 Federation: X Regions`) with direct link to region management modal.
  - Dedicated Multi-Region Edge Peer Federation card with 5 live KPI counters (Active Regions, Healthy Peers, Avg WAN Latency, In-Flight Syncs, Routed Containers).
  - Tabbed interface switching between Edge Regions table and Geo-Distributed Container Routes table with failover trigger actions.
  - Federation Management Modal (`#federation-modal`) enabling peer region registration, test sync execution, failover drills, and configuration updates.
- Command-Line Flags & Environment Variables (`main.go`):
  - Added `--federation`, `--federation-region`, `--federation-name`, `--federation-key`, and `--wan-sync-interval` with matching environment variable bindings (`DOCK_RADAR_FEDERATION`, `DOCK_RADAR_FEDERATION_REGION`, `DOCK_RADAR_FEDERATION_NAME`, `DOCK_RADAR_FEDERATION_KEY`, `DOCK_RADAR_WAN_SYNC_INTERVAL`).

## [2.0.0] - 2026-10-16

### Added
- Adaptive Kernel eBPF Telemetry & Behavioral Security Engine (`internal/ebpf/`):
  - Pure standard-library socket connection flow tracker tracing active TCP/UDP sockets, connection states (ESTABLISHED, LISTEN, TIME_WAIT), throughput counters, and estimated RTT latency (`internal/ebpf/flow.go`, `internal/ebpf/flow_test.go`).
  - Native Linux `/proc/net/tcp` and `/proc/net/tcp6` little-endian hex address and socket table decoder with container network namespace PID correlation and portable fallback engine for non-Linux hosts (`internal/ebpf/probe.go`, `internal/ebpf/probe_test.go`).
  - Behavioral system call and container anomaly detection engine with built-in threat rules: interactive shell execution (`execve`), privilege escalation (`setuid`), ptrace injection, sensitive credential access (`/etc/shadow`), Docker socket mount abuse, and suspicious cryptominer outbound connections (`internal/ebpf/security.go`, `internal/ebpf/security_test.go`).
  - Central eBPF Engine orchestrating adaptive sampling backpressure, thread-safe configuration updates, container discovery correlation, and alert webhook dispatch (`internal/ebpf/engine.go`, `internal/ebpf/engine_test.go`).
- eBPF & Kernel Security REST APIs (`internal/api/ebpf.go`, `internal/api/ebpf_test.go`):
  - `GET /api/ebpf/status`: Returns probe mode, host kernel information, active flows, and probe CPU overhead percentage (requires `RoleViewer`).
  - `GET /api/ebpf/flows`: Queries tracked container socket flows with filtering by container ID, state, protocol, and result limits (requires `RoleViewer`).
  - `GET /api/ebpf/security/events`: Lists recent container security anomaly alerts with severity and container filters (requires `RoleViewer`).
  - `GET /api/ebpf/security/rules`: Returns active threat detection rules and patterns (requires `RoleViewer`).
  - `POST /api/ebpf/security/rules`: Updates security ruleset or toggles individual rules via quick toggle queries (requires `RoleAdmin`).
  - `POST /api/ebpf/reset`: Resets active socket flows and security anomaly history (requires `RoleAdmin`).
  - `POST /api/ebpf/trigger-test`: Simulates test anomaly events to verify notification pathways and UI reaction (requires `RoleAdmin`).
- Prometheus Metrics Exporter Extension (`internal/metrics/ebpf.go`, `internal/metrics/prometheus.go`):
  - Exposes `dock_radar_ebpf_flows_active`, `dock_radar_ebpf_flows_total`, `dock_radar_ebpf_bytes_ingress_total`, `dock_radar_ebpf_bytes_egress_total`, `dock_radar_ebpf_security_alerts_total`, `dock_radar_ebpf_syscalls_traced_total`, `dock_radar_ebpf_cpu_overhead_percent`, and `dock_radar_ebpf_probe_active` metrics for Grafana monitoring.
- Embedded Dark-Mode Dashboard Glassmorphism UI (`web/dist/index.html`):
  - Header eBPF status pill (`⚡ eBPF: X Flows`) with direct launcher to rules configuration modal.
  - Dedicated Kernel eBPF Telemetry card with live KPI metrics (Active Sockets, Bandwidth Throughput, Traced Syscalls, Security Anomalies, CPU Overhead).
  - Tabbed interface switching between real-time socket connection flows table and security incident feed with mitigation guidance.
  - Threat Rules & Probe Configuration Modal (`#ebpf-modal`) enabling one-click rule toggling, probe status inspection, and simulated test anomaly triggers.
- Command-Line Flags & Environment Variables (`main.go`):
  - Added `--ebpf`, `--ebpf-mode`, and `--ebpf-interval` with matching environment variable bindings (`DOCK_RADAR_EBPF_ENABLED`, `DOCK_RADAR_EBPF_MODE`, `DOCK_RADAR_EBPF_INTERVAL`).

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
