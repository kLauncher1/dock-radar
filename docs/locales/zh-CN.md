<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <b>🇨🇳 简体中文</b> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**内置实时深色模式 Web 仪表板的超轻量级单二进制容器与系统指标监控引擎。**

[![Release](https://img.shields.io/badge/Release-v2.0.0-38bdf8.svg?style=flat)](https://github.com/kLauncher1/dock-radar/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6%2B-3178C6.svg?style=flat&logo=typescript)](https://www.typescriptlang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Memory Footprint](https://img.shields.io/badge/Memory_Footprint-<15MB-10b981.svg)](#-架构与安全性-architecture--security)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-快速开始-quick-start)

<sub>由 **kLauncher1** 精心构建 · 专为家庭实验室、服务器和边缘节点的极低资源开销而设计。</sub>

</div>

---

## ⚡ 核心亮点 (Highlights)

- **单可执行二进制部署**: Web 仪表板通过 Go 的 `//go:embed` 指令直接打包在二进制程序内部。无需 Node.js 运行时、外部静态资源或独立前端服务器。
- **超低内存占用**: 基于有界循环环形缓冲区（Circular Ring Buffer），常驻运行内存**低于 15 MB RAM**，非常适合低配 VPS、树莓派（Raspberry Pi）和家庭实验室环境。
- **自适应内核 eBPF 遥测与行为安全引擎**: 基于纯标准库的套接字流跟踪器和 Linux `/proc/net/tcp` 检查器，实时测量 TCP/UDP 连接数、字节吞吐量和往返延迟（RTT）。内置行为安全引擎监控容器系统调用，配备自动化检测规则，识别异常 shell 执行（`execve`）、特权提升（`setuid`）、内存检查（`ptrace`）、访问敏感凭据（`/etc/shadow`）、Docker 套接字滥用以及出站挖矿连接，并提供实时可视化流监控和安全事件流。
- **分布式临时日志存储与 S3 转储**: 将内存中的容器日志压缩为具备 SHA-256 加密完整性校验和原子磁盘写入的 gzip（`.gz`）数据块。后台异步转储器利用纯标准库 AWS SigV4 签名器将日志块流式传输到兼容 S3 的云对象存储（AWS S3、MinIO、Cloudflare R2），支持本地磁盘容量上限、基于时间的轮转清理、转储优先保留裁剪以及专用数据块浏览器和直接下载。
- **零停机滚动重启与流量排空 (Zero-Downtime Rolling Restarts)**: 跨副本、Compose 栈或标签组按序编排容器重启。包含具备可配置超时和反向代理 Webhook 通知的高雅运行中流量排空、多阶段容器就绪性探测（Docker 状态、容器健康检查、HTTP `/healthz` 端点、就绪宽限窗口），以及级联故障时的自动回滚中止触发器。
- **动态多节点集群网格与 Gossip 发现**: 零配置局域网 UDP 广播自动发现（端口 9085）与轻量级 SWIM Gossip 协议相结合。支持直接随机 Ping/Ack、间接协助 Ping（$k=3$）、怀疑监视计时器、化身反驳（Incarnation Refutation）以及去中心化集群健康共识，在 Web 仪表板中提供专用多主机卡片。
- **预测性异常检测与 OOM 耗尽雷达**: 实时普通最小二乘法（OLS）线性回归趋势分析，预测内存饱和斜率（$m$）、截距（$c$）及动态耗尽时间（TTE, Time-to-Exhaustion）。在内核 OOM Killer 终止容器之前提前发送 Webhook 告警，并在 Web 仪表板上显示倒计时仪表盘和趋势卡片。
- **自主自愈（Self-Healing）容器引擎**: 当发生 OOM 崩溃退出（`exit 137`）或异常抖动状态时，自动触发容器修复规则，受抖动指数退避、熔断隔离阈值及实时 Prometheus 遥测指标保护。
- **Docker Compose 拓扑与栈可视化器**: 根据 `com.docker.compose.project` 标签自动对容器进行分组，通过交互式 SVG 依赖拓扑图展示架构服务层级（数据库、缓存、队列、网关、工作节点），支持全栈生命周期操作（重启、停止、重新创建）和专用指标。
- **浏览器内交互式容器终端 (Exec)**: 基于 WebSocket（`/api/docker/exec`）的全双工交互式 shell 终端，支持高保真 VT100 / ANSI 转义序列渲染（256 色）、只读策略强制执行及空闲会话自动断开。
- **多主机代理网格与远程节点聚合器**: 跨多台服务器拓扑实现实时跨主机容器监控。支持动态节点注册、节点健康探测、往返延迟跟踪与统一多节点指标聚合。
- **Prometheus 标准指标导出器**: 提供原生 `/metrics` 端点，按照 Prometheus  exposition 格式导出主机、容器、网格节点、告警及审计日志指标，便于接入 Grafana。
- **批量容器管理操作**: 支持一键式和 API 驱动的同步生命周期操作（`restart_all`、`stop_all`）以及安全的闲置容器清理（`prune`）。
- **线程安全的审计跟踪日志 (Audit Trail)**: 固定容量的环形缓冲区最多记录 2,000 条安全和管理操作，支持流式 NDJSON 和 JSON 导出（`/api/audit/export`）。
- **自动化 TLS 传输加密**: 内存 TLS 证书引擎自动为 localhost、回环地址和网络接口生成带有 SAN 的 ECDSA P-256 自签名证书。同时完全支持通过命令行参数或环境变量配置自定义证书。
- **Bearer 令牌认证与 RBAC 权限控制**: 细粒度的角色访问控制，区分 `admin`（完全生命周期控制、告警规则、日志流）与 `viewer`（只读遥测和日志流），并采用常量时间比较（`subtle.ConstantTimeCompare`）抵御时序侧信道攻击。
- **自动化 Webhook 告警通知**: 容器意外退出、崩溃或发生重启循环时，立即向 Discord（彩色卡片）和 Slack（格式化附件）发送 Webhook 告警。
- **故障频率与抖动检测 (Flapping Detection)**: 滑动窗口监控跟踪快速容器重启周期，在服务器发生全面故障前提前捕捉抖动和崩溃循环。
- **主机资源阈值监控**: 支持可配置的 CPU 和内存使用率阈值，具备自动告警去重和冷却时间控制。
- **实时容器日志流传输**: 纯标准库 RFC 6455 WebSocket 流式传输（`/api/docker/logs`），具备 Docker 多路复用 stdout/stderr 解复用功能，并在不支持时优雅降级为 REST JSON 快照。
- **Docker 套接字检查与生命周期控制**: 检查活动容器，并通过确认对话框提供一键式安全容器重启、停止和批量操作。
- **主机系统遥测**: 实时跟踪 CPU 核心数、goroutine 数量、分配的 RAM、垃圾回收（GC）周期和系统运行时间。
- **多平台二进制构建矩阵**: 为 Linux（amd64、arm64）、macOS（amd64、arm64 Apple Silicon）和 Windows（amd64）进行了编译与验证。

---

## 🚀 快速开始 (Quick Start)

### 1. 下载并运行（独立二进制）

```bash
# 克隆仓库
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# 使用 Go 直接运行（默认 HTTP 端口 9080）
go run .
```

嵌入式 Web 控制台可立即在浏览器中访问：
👉 **`http://localhost:9080`**

### 2. 启用 TLS 与身份验证运行（生产安全模式）

```bash
# 启用自动自签名 TLS 并设置管理员和只读访问令牌
go run . --tls --admin-token="my-super-secret-admin-token" --viewer-token="my-readonly-token"
```

安全 Web 控制台访问地址：
👉 **`https://localhost:9080`**

### 3. 构建单二进制文件

```bash
# 编译去除了调试符号的小型独立可执行文件
go build -ldflags="-s -w" -o dock-radar .

# 运行二进制文件
./dock-radar --help
```

### 4. 配置选项与环境变量

| 参数标志 | 环境变量 | 默认值 | 描述 |
| :--- | :--- | :--- | :--- |
| `--port` | `PORT` | `9080` | 仪表板和 API 监听的 TCP 端口 |
| `--tls` | `DOCK_RADAR_TLS` | `false` | 启用带有自动生成或自定义证书的 HTTPS 传输 |
| `--tls-cert` | `DOCK_RADAR_TLS_CERT` | `""` | 自定义 TLS 证书 PEM 文件路径 |
| `--tls-key` | `DOCK_RADAR_TLS_KEY` | `""` | 自定义 TLS 私钥 PEM 文件路径 |
| `--admin-token` | `DOCK_RADAR_ADMIN_TOKEN` | `""` | 授予完全管理控制权限的 Bearer 令牌 |
| `--viewer-token` | `DOCK_RADAR_VIEWER_TOKEN`| `""` | 授予只读遥测访问权限的 Bearer 令牌 |
| `--allow-remote` | `DOCK_RADAR_ALLOW_REMOTE`| `false` | 允许外部网络请求，无需回环地址检查 |
| `--nodes` | `DOCK_RADAR_NODES` | `""` | 要聚合的远程 dock-radar 节点地址列表（逗号分隔） |
| `--node-name` | `DOCK_RADAR_NODE_NAME` | `hostname` | 当前节点在仪表板中的显示名称 |
| `--mesh-discovery` | `DOCK_RADAR_MESH_DISCOVERY` | `false` | 启用零配置 UDP 广播局域网节点自动发现 |
| `--mesh-port` | `DOCK_RADAR_MESH_PORT` | `9085` | 局域网节点自动发现信标的 UDP 端口 |
| `--gossip-interval` | `DOCK_RADAR_GOSSIP_INTERVAL` | `5s` | SWIM 去中心化集群 Gossip Ping 间隔 |
| `--version` | — | — | 打印 dock-radar 版本并退出 |

---

## 🏛️ 架构与安全性 (Architecture & Security)

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
│   internal/mesh          │      internal/logs          │
│   • Node Discovery/Probe │      • Circular Ring Buffer │
│   • Aggregate Telemetry  │      • Strict <15MB Ceiling │
│   • SWIM Gossip Protocol │                             │
│   • UDP Broadcast Beacon │                             │
├──────────────────────────┼─────────────────────────────┤
│   internal/alert         │      internal/audit         │
│   • Discord & Slack Web  │      • Circular Event Log   │
│   • State Poller/Flap    │      • NDJSON / JSON Export │
│   • Cooldown Deduplication                             │
├──────────────────────────┼─────────────────────────────┤
│   internal/healing       │      net/http Router        │
│   • Auto OOM / Crash Loop│      • /metrics (Prometheus)│
│   • Jitter & Backoff     │      • /api/docker/*        │
│   • Circuit Breaker      │      • /api/healing/*       │
├──────────────────────────┤      • /api/nodes/*         │
│   internal/metrics       │      • /api/cluster/*       │
│   • Standard Prometheus  │      • /api/mesh/*          │
│   • Exposition Formatter │      • /api/audit/*         │
│   • Multi-Node Mesh Stats│      • Pure RFC 6455 WS     │
├──────────────────────────┤                             │
│   internal/security      │                             │
│   • In-Memory ECDSA TLS  │                             │
│   • Constant-Time Bearer │                             │
│   • RBAC (Admin/Viewer)  │                             │
├──────────────────────────┴─────────────────────────────┤
│                 Embedded Web Dashboard                 │
│         (React 19 + TypeScript / Vite Bundled)         │
│          //go:embed web/dist/* -> Port 9080            │
└────────────────────────────────────────────────────────┘
```

### 安全保障 (Security Guarantees)
- **传输层加密 (TLS)**: 支持在内存中自动生成带 SAN 验证的 ECDSA P-256 自签名证书，覆盖所有主机网络接口，同时支持企业自定义证书绑定。
- **常量时间身份验证**: 令牌验证依托 `crypto/subtle.ConstantTimeCompare`，杜绝 API 令牌上的时序侧信道分析。
- **细粒度 RBAC 分离**: 读取端点（系统指标、容器列表、日志流）对 `viewer` 和 `admin` 开放，破坏性操作（重启、停止、告警变更）严格要求 `admin` 角色。
- **回环地址默认策略**: 未配置认证令牌时，写操作端点仅限本地回环接口（`127.0.0.1`、`::1`、`localhost`）访问。
- **防范 CSRF 与 DNS 重绑定**: 严格校验现代浏览器元数据（`Sec-Fetch-Site`）及 `Origin`/`Referer` 标头，防御跨域驱动型攻击。
- **防范 SSRF 与元数据拦截**: Webhook 目标强制执行 HTTP/HTTPS 协议，过滤换行符（CRLF），明确拒绝云实例元数据端点（`169.254.169.254`、`metadata.google.internal`）。
- **参数边界过滤**: 所有容器 ID 和名称都通过严格的字母数字模式（`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`）验证，防止路径遍历与套接字注入。
- **速率限制保护**: 令牌桶速率限制器将容器操作及告警控制调用限制为突发 5 次，每秒填充 1 个令牌。

---

## 📡 REST 与 WebSocket API 参考

| 端点 | 方法 / 协议 | 所需角色 | 描述 |
| :--- | :---: | :---: | :--- |
| `/metrics` | `GET` | `viewer` | 供 Grafana 抓取的标准 Prometheus 格式指标端点 |
| `/api/system` | `GET` | `viewer` | 主机名、操作系统/架构、CPU 核心、活动协程数、分配内存（MB）、GC 次数及运行时间 |
| `/api/docker` | `GET` | `viewer` | Docker 守护进程连接状态、容器总数与运行数及容器详细信息 |
| `/api/docker/batch` | `POST` | `admin` | 容器批量操作：`restart_all`、`stop_all`、`prune` (`{"action":"restart_all","timeout":10}`) |
| `/api/docker/logs` | `WS` / `GET` | `viewer` | 实时 WebSocket 日志流或 JSON 快照 (`?id=<id>&stream=<stdout\|stderr\|system>&tail=100`) |
| `/api/docker/restart` | `POST` | `admin` | 通过 ID 或名称安全重启容器 (`{"id":"<name_or_id>","timeout":10}`) |
| `/api/docker/stop` | `POST` | `admin` | 安全停止运行中的容器 (`{"id":"<name_or_id>","timeout":10}`) |
| `/api/healing/config` | `GET` / `POST` | `viewer` / `admin` | 查询或更新自动自愈策略、抖动上限和隔离排除规则 |
| `/api/healing/status` | `GET` | `viewer` | 活动自愈指标、受隔离容器列表与退避状态 |
| `/api/healing/history`| `GET` | `viewer` | 最近的自愈事件历史记录日志 (`?limit=50&container=`) |
| `/api/healing/reset`  | `POST` | `admin` | 清除容器的熔断隔离状态并重置退避计数器 |
| `/api/nodes` | `GET` / `POST` / `DELETE` | `viewer` / `admin` | 节点清单列表、动态远程节点注册与注销 |
| `/api/nodes/heartbeat` | `POST` | `viewer` | 远程代理遥测与容器同步推送端点 |
| `/api/cluster/summary` | `GET` | `viewer` | 集群聚合指标（总节点数、在线/离线节点、CPU、内存、容器总数） |
| `/api/cluster/containers` | `GET` | `viewer` | 跨所有集群节点的统一样式容器清单 (`?node_id=&state=`) |
| `/api/mesh/discovery` | `GET` / `POST` | `viewer` / `admin` | 局域网 UDP 自动发现节点状态与手动广播信标 (`POST {"action":"broadcast"}`) |
| `/api/mesh/gossip` | `GET` / `POST` | `viewer` / `none` | 集群 SWIM Gossip 成员状态与 P2P 消息接收 |
| `/api/audit/export` | `GET` | `viewer` | 导出 NDJSON 或 JSON 格式的审计日志 (`?format=ndjson&limit=2000&action=`) |
| `/api/alerts/config` | `GET` / `POST` | `viewer` / `admin` | 获取或更新活动告警规则、Webhook 接收地址和阈值设置 |
| `/api/alerts/events` | `GET` | `viewer` | 获取近期触发的事件和告警历史缓冲区 (`?limit=50`) |
| `/api/alerts/test` | `POST` | `admin` | 立即向 Discord 或 Slack 发送测试 Webhook 载荷 |
| `/api/auth/status` | `GET` | `none` | 返回 TLS 状态、远程访问模式、认证需求与当前角色 |
| `/api/auth/verify` | `POST` | `none` | 验证客户端 Bearer 令牌并返回已授予的访问权限角色 |
| `/` | `GET` | `none` | 提供内置单页 Web 仪表板界面 |

---

## 🗺️ 发展路线 (Roadmap)

有关里程碑目标、即将推出的功能和发布历史，请参阅 [ROADMAP.md](../../ROADMAP.md)。

---

## 🔒 安全性 (Security)

有关漏洞披露和报告流程，请参阅 [SECURITY.md](../../SECURITY.md)。

---

## 📄 许可证 (License)

在 [Apache License 2.0](../../LICENSE) 许可下发布。
