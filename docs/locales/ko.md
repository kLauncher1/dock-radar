<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <b>🇰🇷 한국어</b> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**실시간 다크모드 웹 대시보드가 내장된 초경량 단일 바이너리 컨테이너 및 호스트 시스템 메트릭 모니터.**

[![Release](https://img.shields.io/badge/Release-v2.0.0-38bdf8.svg?style=flat)](https://github.com/kLauncher1/dock-radar/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6%2B-3178C6.svg?style=flat&logo=typescript)](https://www.typescriptlang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Memory Footprint](https://img.shields.io/badge/Memory_Footprint-<15MB-10b981.svg)](#-아키텍처--보안-architecture--security)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-빠른-시작-quick-start)

<sub>**kLauncher1** 제작 · 홈랩, 서버 및 엣지 노드를 위한 초저자원 오버헤드 설계.</sub>

</div>

---

## ⚡ 주요 특징 (Highlights)

- **단일 실행 바이너리 배포**: Go의 `//go:embed` 지시문을 통해 웹 대시보드가 바이너리 내부에 직접 번들링되어 있습니다. 별도의 Node.js 런타임, 외부 정적 자산, 독립 웹 서버가 전혀 필요하지 않습니다.
- **초저용량 메모리 점유**: 크기 제한이 적용된 원형 링 버퍼(Circular Ring Buffer)를 기반으로 상시 **15 MB 미만의 RAM**으로 동작하여 저사양 VPS, 라즈베리 파이(Raspberry Pi), 홈랩 환경에 최적화되어 있습니다.
- **적응형 커널 eBPF 텔레메트리 및 행동 분석 보안 엔진**: 순수 표준 라이브러리 기반 소켓 플로우 트래커 및 Linux `/proc/net/tcp` 인스펙터로 실시간 TCP/UDP 연결, 바이트 처리량, 왕복 지연 시간(RTT)을 측정합니다. 내장된 행동 보안 엔진은 비정상 셸 실행(`execve`), 권한 상승(`setuid`), 메모리 검사(`ptrace`), 호스트 민감 자격 증명 접근(`/etc/shadow`), 도커 소켓 오용, 외부 채굴 연결 등을 실시간 탐지하고 시각적 플로우 모니터와 보안 인시던트 피드를 제공합니다.
- **분산 임시 로그 스토리지 및 S3 오프로더**: 인메모리 컨테이너 로그를 암호화 SHA-256 무결성 검증 및 원자적 디스크 쓰기가 적용된 gzip(`.gz`) 청크로 압축합니다. 백그라운드 비동기 오프로더는 표준 라이브러리 기반 AWS SigV4 서명기를 사용하여 S3 호환 클라우드 스토리지(AWS S3, MinIO, Cloudflare R2)로 청크를 스트리밍하며, 디스크 용량 한도, 보존 주기 정리, 전용 청크 뷰어 및 다운로드를 지원합니다.
- **무중단 롤링 재시작 및 트래픽 드레이닝 (Zero-Downtime Rolling Restarts)**: 레플리카, Compose 스택, 라벨 그룹 단위로 컨테이너를 순차적으로 재시작합니다. 역방향 프록시 웹훅 알림을 포함한 진행 중 트래픽 드레이닝, 다단계 헬스체크 준비성 프로빙(Docker 상태, 헬스체크, HTTP `/healthz`, 유예 시간), 연속 실패 시 다운타임을 차단하는 자동 롤백 중단 트리거를 탑재했습니다.
- **동적 멀티 노드 클러스터 메시 및 가십(Gossip) 디스커버리**: LAN UDP 브로드캐스트 자동 탐색(포트 9085)과 경량 SWIM 기반 가십 프로토콜을 결합했습니다. 무작위 직접 핑/응답, 간접 헬퍼 핑($k=3$), 의심 감시 타이머, 인카네이션 반박 및 탈중앙화 헬스 합의를 웹 대시보드 멀티 호스트 카드에서 직관적으로 확인할 수 있습니다.
- **예측형 이상 탐지 및 OOM 고갈 레이더**: 실시간 OLS(Ordinary Least Squares) 선형 회귀 분석을 통해 메모리 포화 기울기($m$), 절편($c$), 동적 고갈 예상 시간(TTE, Time-to-Exhaustion)을 예측합니다. 커널 OOM 킬러가 컨테이너를 강제 종료하기 전에 조기 경보 웹훅을 발송하며, 대시보드에 카운트다운 게이지를 표시합니다.
- **자율 자가 치유(Self-Healing) 컨테이너 엔진**: OOM 비정상 종료(`exit 137`) 및 비정상 플래핑 상태 감지 시 자동 복구 규칙을 실행하며, 지터 기반 지수 백오프, 서킷 브레이커 격리 임계값, Prometheus 텔레메트리로 보호됩니다.
- **Docker Compose 토폴로지 및 스택 시각화**: `com.docker.compose.project` 라벨로 컨테이너를 자동 그룹화하고 대화형 SVG 토폴로지 그래프로 종속성을 시각화합니다. 아키텍처 계층 감지(DB, 캐시, 큐, 게이트웨이, 워커), 스택 단위 수명주기 제어(재시작, 정지, 재생성), 전용 스택 메트릭을 지원합니다.
- **브라우저 내장 대화형 컨테이너 터미널 (Exec)**: WebSocket(`/api/docker/exec`) 기반 전이중 대화형 셸 터미널로 256색 VT100 / ANSI 이스케이프 시퀀스 렌더링, 읽기 전용 정책 강제, 유휴 세션 자동 종료를 지원합니다.
- **멀티 호스트 에이전트 메시 및 원격 노드 수집기**: 분산 서버 간 실시간 컨테이너 모니터링을 제공합니다. 동적 노드 등록, 피어 헬스 프로빙, RTT 지연 측정, 통합 멀티 노드 텔레메트리를 지원합니다.
- **Prometheus 표준 메트릭 익스포터**: 호스트, 컨테이너, 메시 노드, 경보, 감사 로그 텔레메트리를 Grafana 수집에 맞춘 표준 형식으로 노출하는 `/metrics` 엔드포인트를 제공합니다.
- **배치 컨테이너 오퍼레이션**: 원클릭 및 API 기반 동기화 일괄 제어(`restart_all`, `stop_all`) 및 안전한 미사용 컨테이너 정리(`prune`)를 지원합니다.
- **스레드 안전 감사 추적 로그 (Audit Trail)**: 최대 2,000건의 보안 및 관리 액션을 링 버퍼에 기록하며 스트리밍 NDJSON 및 JSON 내보내기(`/api/audit/export`)를 지원합니다.
- **자동 TLS 전송 보안**: 인메모리 TLS 인증서 엔진이 localhost, 루프백 및 네트워크 인터페이스를 위한 ECDSA P-256 자체 서명 인증서와 SAN을 자동 생성합니다. CLI 플래그 및 환경 변수를 통한 커스텀 인증서도 지원합니다.
- **Bearer 토큰 인증 및 RBAC 권한 분리**: 모든 수명주기 제어가 가능한 `admin` 권한과 읽기 전용인 `viewer` 권한을 분리하며, 타이밍 사이드 채널 공격을 원천 차단하는 상수 시간 토큰 비교(`subtle.ConstantTimeCompare`)를 적용했습니다.
- **자동 웹훅 경보 발송**: 예기치 않은 컨테이너 종료, 크래시 또는 무한 재시작 루프 발생 시 Discord(색상 임베드) 및 Slack(서식 첨부)으로 즉시 웹훅 알림을 발송합니다.
- **장애 빈도 및 플래핑 감지**: 슬라이딩 윈도우 기반 감시로 단시간 내 빈번한 재시작을 감지하여 서비스 중단 전에 조기 경보를 발생시킵니다.
- **호스트 자원 임계값 감시**: CPU 및 메모리 사용률 임계값 설정과 자동 알림 중복 제거 및 쿨다운 제어를 제공합니다.
- **실시간 컨테이너 로그 스트리밍**: RFC 6455 표준 WebSocket(`/api/docker/logs`)을 통한 실시간 로그 스트리밍과 도커 stdout/stderr 디멀티플렉싱 및 JSON 스냅샷 폴백을 지원합니다.
- **도커 소켓 인스펙션 및 수명주기 제어**: 활성 컨테이너를 안전하게 검사하고 확인 대화상자를 거쳐 컨테이너를 재시작, 중지 또는 일괄 정리합니다.
- **호스트 시스템 텔레메트리**: 실시간 CPU 코어, 고루틴, 할당 메모리, GC 사이클 및 가동 시간을 정밀 추적합니다.
- **크로스 플랫폼 독립 바이너리**: Linux(amd64, arm64), macOS(amd64, arm64 Apple Silicon), Windows(amd64) 전 플랫폼을 검증 완료했습니다.

---

## 🚀 빠른 시작 (Quick Start)

### 1. 다운로드 및 실행 (독립 실행형 바이너리)

```bash
# 저장소 복제
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# Go 직접 실행 (기본 HTTP 포트 9080)
go run .
```

내장 웹 대시보드는 브라우저에서 즉시 접속할 수 있습니다:
👉 **`http://localhost:9080`**

### 2. TLS 및 인증 적용 실행 (프로덕션 보안 모드)

```bash
# 자동 자체 서명 TLS 활성화 및 관리자/조회자 토큰 설정
go run . --tls --admin-token="my-super-secret-admin-token" --viewer-token="my-readonly-token"
```

보안 웹 콘솔은 다음 주소로 접속 가능합니다:
👉 **`https://localhost:9080`**

### 3. 단일 바이너리 빌드

```bash
# 불필요한 디버그 기호를 제거한 초경량 독립 실행 파일 빌드
go build -ldflags="-s -w" -o dock-radar .

# 바이너리 도움말 확인
./dock-radar --help
```

### 4. 구성 옵션 및 환경 변수

| CLI 플래그 | 환경 변수 | 기본값 | 설명 |
| :--- | :--- | :--- | :--- |
| `--port` | `PORT` | `9080` | 대시보드 및 API 리스너 TCP 포트 |
| `--tls` | `DOCK_RADAR_TLS` | `false` | 자동 생성 또는 사용자 지정 인증서를 사용한 HTTPS 활성화 |
| `--tls-cert` | `DOCK_RADAR_TLS_CERT` | `""` | 커스텀 TLS 인증서 PEM 파일 경로 |
| `--tls-key` | `DOCK_RADAR_TLS_KEY` | `""` | 커스텀 TLS 개인키 PEM 파일 경로 |
| `--admin-token` | `DOCK_RADAR_ADMIN_TOKEN` | `""` | 모든 관리자 제어 권한을 부여하는 Bearer 토큰 |
| `--viewer-token` | `DOCK_RADAR_VIEWER_TOKEN`| `""` | 읽기 전용 텔레메트리 조회를 허용하는 Bearer 토큰 |
| `--allow-remote` | `DOCK_RADAR_ALLOW_REMOTE`| `false` | 루프백 체크 없이 외부 네트워크 요청 허용 |
| `--nodes` | `DOCK_RADAR_NODES` | `""` | 수집할 원격 dock-radar 노드 주소 목록 (쉼표 구분) |
| `--node-name` | `DOCK_RADAR_NODE_NAME` | `hostname` | 대시보드에 표시될 현재 노드의 이름 |
| `--mesh-discovery` | `DOCK_RADAR_MESH_DISCOVERY` | `false` | LAN UDP 브로드캐스트 기반 노드 자동 탐색 활성화 |
| `--mesh-port` | `DOCK_RADAR_MESH_PORT` | `9085` | LAN 피어 자동 탐색 비콘 UDP 포트 |
| `--gossip-interval` | `DOCK_RADAR_GOSSIP_INTERVAL` | `5s` | SWIM 탈중앙화 클러스터 가십 핑 주기 |
| `--version` | — | — | dock-radar 버전 출력 후 종료 |

---

## 🏛️ 아키텍처 & 보안 (Architecture & Security)

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

### 보안 보증 (Security Guarantees)
- **전송 계층 암호화 (TLS)**: 모든 호스트 네트워크 인터페이스에 대한 SAN 검증이 포함된 인메모리 ECDSA P-256 자체 서명 인증서 생성 및 엔터프라이즈 맞춤형 인증서 번들을 지원합니다.
- **상수 시간 인증**: 토큰 검증은 `crypto/subtle.ConstantTimeCompare`를 사용하여 API 토큰에 대한 타이밍 사이드 채널 공격을 원천 무력화합니다.
- **세분화된 RBAC 권한 분리**: 조회 엔드포인트(시스템 메트릭, 컨테이너 목록, 로그 스트림)는 `viewer` 및 `admin` 모두 접근 가능하며, 변경 및 파괴적 작업(재시작, 정지, 알림 수정)은 `admin` 권한이 엄격히 요구됩니다.
- **루프백 기본 차단 정책**: 인증 토큰이 설정되지 않은 경우, 상태를 변경하는 엔드포인트는 로컬 루프백 인터페이스(`127.0.0.1`, `::1`, `localhost`)로만 접근이 엄격히 제한됩니다.
- **CSRF 및 DNS Rebinding 방어**: 최신 브라우저 메타데이터(`Sec-Fetch-Site`) 및 `Origin`/`Referer` 헤더를 검증하여 악성 웹사이트를 통한 교차 출처 드라이브 바이 공격을 차단합니다.
- **SSRF 및 클라우드 메타데이터 차단**: 웹훅 전송 대상은 엄격한 HTTP/HTTPS 스킴을 강제하고, 개행 문자(CRLF)를 필터링하며, 클라우드 인스턴스 메타데이터 주소(`169.254.169.254`, `metadata.google.internal`)를 명시적으로 거부합니다.
- **매개변수 경계 검증**: 모든 컨테이너 ID 및 이름은 엄격한 영숫자 패턴(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)으로 검증되어 경로 조작(Path Traversal) 및 소켓 인젝션을 방지합니다.
- **속도 제한(Rate-Limiting) 보호**: 토큰 버킷 속도 제한기가 컨테이너 제어 및 알림 API 호출을 초당 1개 리필 기준 최대 5개 작업으로 제한합니다.

---

## 📡 REST & WebSocket API 레퍼런스

| 엔드포인트 | 메서드 / 프로토콜 | 필요 권한 | 설명 |
| :--- | :---: | :---: | :--- |
| `/metrics` | `GET` | `viewer` | Grafana 연동용 표준 Prometheus 메트릭 수집 엔드포인트 |
| `/api/system` | `GET` | `viewer` | 호스트명, OS/Arch, CPU 코어, 활성 고루틴, 메모리(MB), GC 횟수 및 가동 시간 |
| `/api/docker` | `GET` | `viewer` | 도커 데몬 연결 상태, 전체 및 실행 중인 컨테이너 수, 컨테이너 상세 정보 |
| `/api/docker/batch` | `POST` | `admin` | 컨테이너 일괄 제어: `restart_all`, `stop_all`, `prune` (`{"action":"restart_all","timeout":10}`) |
| `/api/docker/logs` | `WS` / `GET` | `viewer` | 실시간 WebSocket 로그 피드 또는 JSON 스냅샷 (`?id=<id>&stream=<stdout\|stderr\|system>&tail=100`) |
| `/api/docker/restart` | `POST` | `admin` | ID 또는 이름으로 컨테이너 안전 재시작 (`{"id":"<name_or_id>","timeout":10}`) |
| `/api/docker/stop` | `POST` | `admin` | 실행 중인 컨테이너 안전 중지 (`{"id":"<name_or_id>","timeout":10}`) |
| `/api/healing/config` | `GET` / `POST` | `viewer` / `admin` | 자동 복구 정책, 지터 한도, 격리 예외 규칙 조회 및 업데이트 |
| `/api/healing/status` | `GET` | `viewer` | 활성 치유 메트릭, 격리된 컨테이너 목록, 백오프 진행 상태 |
| `/api/healing/history`| `GET` | `viewer` | 최근 자동 복구 이벤트 히스토리 로그 (`?limit=50&container=`) |
| `/api/healing/reset`  | `POST` | `admin` | 특정 컨테이너의 서킷 브레이커 격리를 해제하고 백오프 카운터 초기화 |
| `/api/nodes` | `GET` / `POST` / `DELETE` | `viewer` / `admin` | 노드 인벤토리 목록, 동적 원격 노드 등록 및 등록 해제 |
| `/api/nodes/heartbeat` | `POST` | `viewer` | 원격 에이전트 텔레메트리 및 컨테이너 동기화 푸시 엔드포인트 |
| `/api/cluster/summary` | `GET` | `viewer` | 클러스터 집계 메트릭 (전체/온라인/오프라인 노드, CPU, 메모리, 총 컨테이너) |
| `/api/cluster/containers` | `GET` | `viewer` | 전체 클러스터 노드에 걸친 통합 컨테이너 인벤토리 (`?node_id=&state=`) |
| `/api/mesh/discovery` | `GET` / `POST` | `viewer` / `admin` | LAN UDP 자동 탐색 피어 상태 및 수동 비콘 브로드캐스트 (`POST {"action":"broadcast"}`) |
| `/api/mesh/gossip` | `GET` / `POST` | `viewer` / `none` | 클러스터 SWIM 가십 멤버십 상태 및 P2P 가십 메시지 수신 |
| `/api/audit/export` | `GET` | `viewer` | NDJSON 또는 JSON 형식으로 감사 추적 로그 내보내기 (`?format=ndjson&limit=2000&action=`) |
| `/api/alerts/config` | `GET` / `POST` | `viewer` / `admin` | 활성 경보 규칙, 웹훅 수신처, 임계값 설정 조회 및 업데이트 |
| `/api/alerts/events` | `GET` | `viewer` | 최근 발생한 인시던트 및 경보 내역 버퍼 조회 (`?limit=50`) |
| `/api/alerts/test` | `POST` | `admin` | Discord 또는 Slack으로 즉시 테스트 웹훅 페이로드 발송 |
| `/api/auth/status` | `GET` | `none` | TLS 상태, 원격 접근 모드, 인증 요구 조건 및 현재 역할 반환 |
| `/api/auth/verify` | `POST` | `none` | 클라이언트 Bearer 토큰 검증 및 부여된 접근 역할 반환 |
| `/` | `GET` | `none` | 내장된 단일 페이지 웹 대시보드 제공 |

---

## 🗺️ 로드맵 (Roadmap)

마일스톤 목표, 향후 추가 예정 기능 및 릴리스 히스토리는 [ROADMAP.md](../../ROADMAP.md)를 참조하세요.

---

## 🔒 보안 (Security)

보안 취약점 제보 및 공개 절차에 대한 내용은 [SECURITY.md](../../SECURITY.md)를 참조하세요.

---

## 📄 라이선스 (License)

[Apache License 2.0](../../LICENSE)에 따라 라이선스가 부여됩니다.
