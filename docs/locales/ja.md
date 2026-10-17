<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <b>🇯🇵 日本語</b> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**リアルタイムのダークモードWebダッシュボードを内蔵した超軽量シングルバイナリコンテナ＆システムメトリクスモニター。**

[![Release](https://img.shields.io/badge/Release-v2.0.0-38bdf8.svg?style=flat)](https://github.com/kLauncher1/dock-radar/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6%2B-3178C6.svg?style=flat&logo=typescript)](https://www.typescriptlang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Memory Footprint](https://img.shields.io/badge/Memory_Footprint-<15MB-10b981.svg)](#-アーキテクチャとセキュリティ-architecture--security)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-クイックスタート-quick-start)

<sub>**kLauncher1** 開発 · ホームラボ、サーバー、エッジノード向けに極限までリソース消費を抑えた設計。</sub>

</div>

---

## ⚡ 主な特徴 (Highlights)

- **単一バイナリによる自己完結型デプロイ**: WebダッシュボードはGoの `//go:embed` ディレクティブによってバイナリ内に直接組み込まれています。Node.jsランタイム、外部静的ファイル、別個のWebサーバーは一切不要です。
- **極小のメモリ使用量**: 容量制限付きのリングバッファ（Circular Ring Buffer）により常時 **15 MB未満のRAM** で動作し、低スペックVPS、Raspberry Pi、ホームラボ環境に最適です。
- **適応型カーネルeBPFテレメトリと振る舞い分析セキュリティエンジン**: 純粋な標準ライブラリによるソケットフロートラッカーとLinux `/proc/net/tcp` インスペクターにより、リアルタイムのTCP/UDP接続、バイトスループット、往復レイテンシ（RTT）を計測します。組み込みの振る舞い検知エンジンは、予期しないシェル実行（`execve`）、権限昇格（`setuid`）、メモリ検査（`ptrace`）、ホスト機密認証情報へのアクセス（`/etc/shadow`）、Dockerソケットの不正利用、外部マイニング接続を自動検知し、ビジュアルフローモニターとインシデントフィードを提供します。
- **分散型エフェメラルログストレージとS3オフローダー**: インメモリのコンテナログを暗号化SHA-256整合性チェックサムとアトミックなディスク書き込みを備えたgzip（`.gz`）チャンクに圧縮します。バックグラウンド非同期オフローダーは標準ライブラリベースのAWS SigV4署名器を使用し、S3互換クラウドストレージ（AWS S3、MinIO、Cloudflare R2）へストリーミングします。ローカルディスク容量制限、期間ベースのローテーション、専用チャンクビューアーと直接ダウンロードをサポートします。
- **ゼロダウンタイム・ローリング再起動とトラフィックドレイン (Zero-Downtime Rolling Restarts)**: レプリカ、Composeスタック、ラベルグループ単位でコンテナの順次再起動を制御します。リバースプロキシWebhook通知を伴う実行中トラフィックのドレイン、多段階コンテナ準備性プロービング（Docker状態、ヘルスチェック、HTTP `/healthz`、準備猶予時間）、連鎖障害を防ぐ自動ロールバック中断トリガーを搭載しています。
- **動的マルチノードクラスタメッシュとGossipディスカバリ**: ゼロ構成のLAN UDPブロードキャスト自動検出（ポート 9085）と軽量SWIMベースのGossipプロトコルを統合。ランダム直接Ping/Ack、間接支援Ping（$k=3$）、疑いタイマー、インカーネーション反論、分散型クラスタヘルス合意をWebダッシュボードの専用マルチホストカードで直感的に表示します。
- **予測型異常検知とOOM枯渇レーダー**: リアルタイムのOLS（Ordinary Least Squares）線形回帰分析により、メモリ飽和の傾き（$m$）、切片（$c$）、動的な枯渇予測時間（TTE, Time-to-Exhaustion）を算出します。カーネルOOMキラーがコンテナを終了させる前に早期警戒Webhookを発行し、ダッシュボード上にカウントダウンゲージを表示します。
- **自律的自己修復（Self-Healing）コンテナエンジン**: OOM強制終了（`exit 137`）や不健全なフラッピング状態を検知した際に自動復旧ルールを実行し、ジッター付き指数バックオフ、サーキットブレーカー隔離閾値、Prometheusテレメトリで保護されます。
- **Docker Composeトポロジーとスタック可視化**: `com.docker.compose.project` ラベルでコンテナを自動グループ化し、インタラクティブなSVGトポロジーグラフで依存関係を可視化します。アーキテクチャ層の識別（DB、キャッシュ、キュー、ゲートウェイ、ワーカー）、スタック単位のライフサイクル操作（再起動、停止、再作成）をサポートします。
- **ブラウザ内蔵インタラクティブコンテナターミナル (Exec)**: WebSocket（`/api/docker/exec`）経由の全二重シェルターミナルで、256色のVT100 / ANSIエスケープシーケンス描画、読み取り専用ポリシー強制、アイドルセッション自動終了をサポートします。
- **マルチホストエージェントメッシュとリモートノードアグリゲーター**: 分散サーバー間のリアルタイムコンテナ監視を実現。動的ノード登録、ピアヘルスプロービング、RTT追跡、統合マルチノードテレメトリを提供します。
- **Prometheus標準メトリクスエクスポーター**: ホスト、コンテナ、メッシュノード、アラート、監査ログをGrafana連携に適した標準形式で出力する `/metrics` エンドポイントを提供します。
- **バッチコンテナ操作**: ワンクリックおよびAPIによる同期一括操作（`restart_all`、`stop_all`）と安全な未使用コンテナ削除（`prune`）をサポートします。
- **スレッドセーフな監査証跡ログ (Audit Trail)**: 最大2,000件のセキュリティおよび管理操作をリングバッファに記録し、NDJSONおよびJSON形式でのエクスポート（`/api/audit/export`）に対応します。
- **自動TLSトランスポート暗号化**: インメモリTLSエンジンがlocalhost、ループバック、ネットワークインターフェース向けにSANを含むECDSA P-256自己署名証明書を自動生成します。CLIフラグや環境変数からのカスタム証明書指定も完全サポートします。
- **Bearerトークン認証とRBACアクセス制御**: 完全なライフサイクル管理が可能な `admin` 権限と読み取り専用の `viewer` 権限を分離し、タイミング攻撃を完全に無効化する定数時間比較（`subtle.ConstantTimeCompare`）を採用しています。
- **自動Webhookアラート通知**: コンテナの予期せぬ終了、クラッシュ、再起動ループ発生時に、Discord（リッチなカラー埋め込み）およびSlack（書式付き添付）へ即時通知します。
- **障害頻度とフラッピング検知 (Flapping Detection)**: スライディングウィンドウ監視により短時間での頻繁な再起動を捉え、システム停止前に早期検知します。
- **ホストリソース閾値監視**: CPUおよびメモリ使用率の閾値設定、アラートの重複排除、クールダウン制御を提供します。
- **リアルタイムコンテナログストリーミング**: RFC 6455準拠のWebSocket（`/api/docker/logs`）によるリアルタイムログ配信とDocker多重化stdout/stderrの分離、REST JSONフォールバックに対応します。
- **Dockerソケット検査とライフサイクル制御**: 稼働中のコンテナを安全に確認し、確認ダイアログ付きで再起動、停止、一括管理を実行できます。
- **ホストシステムテレメトリ**: リアルタイムのCPUコア数、goroutine数、割り当てRAM、GCサイクル、稼働時間を正確にトラッキングします。
- **マルチプラットフォーム対応バイナリ**: Linux（amd64、arm64）、macOS（amd64、arm64 Apple Silicon）、Windows（amd64）で検証済みです。

---

## 🚀 クイックスタート (Quick Start)

### 1. ダウンロードと実行（独立バイナリ）

```bash
# リポジトリのクローン
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# Goで直接実行（デフォルトHTTPポート 9080）
go run .
```

ブラウザから組み込みWebコンソールに即座にアクセスできます：
👉 **`http://localhost:9080`**

### 2. TLSと認証を有効化して実行（本番運用モード）

```bash
# 自動自己署名TLSを有効化し、管理者および閲覧者用トークンを設定
go run . --tls --admin-token="my-super-secret-admin-token" --viewer-token="my-readonly-token"
```

セキュアなWebコンソールのアクセス先：
👉 **`https://localhost:9080`**

### 3. 単一バイナリのビルド

```bash
# 不要なシンボルを除去した軽量な実行可能ファイルのコンパイル
go build -ldflags="-s -w" -o dock-radar .

# バイナリの実行確認
./dock-radar --help
```

### 4. 設定オプションと環境変数

| フラグ | 環境変数 | デフォルト値 | 説明 |
| :--- | :--- | :--- | :--- |
| `--port` | `PORT` | `9080` | ダッシュボードとAPIのリッスンTCPポート |
| `--tls` | `DOCK_RADAR_TLS` | `false` | 自動生成またはカスタム証明書によるHTTPSの有効化 |
| `--tls-cert` | `DOCK_RADAR_TLS_CERT` | `""` | カスタムTLS証明書PEMファイルのパス |
| `--tls-key` | `DOCK_RADAR_TLS_KEY` | `""` | カスタムTLS秘密鍵PEMファイルのパス |
| `--admin-token` | `DOCK_RADAR_ADMIN_TOKEN` | `""` | 完全な管理者制御権限を付与するBearerトークン |
| `--viewer-token` | `DOCK_RADAR_VIEWER_TOKEN`| `""` | 読み取り専用テレメトリ参照を許可するBearerトークン |
| `--allow-remote` | `DOCK_RADAR_ALLOW_REMOTE`| `false` | ループバック確認なしで外部からの接続を許可 |
| `--nodes` | `DOCK_RADAR_NODES` | `""` | 集約対象のリモートdock-radarノードアドレス（カンマ区切り） |
| `--node-name` | `DOCK_RADAR_NODE_NAME` | `hostname` | ダッシュボードに表示する現在のノード名 |
| `--mesh-discovery` | `DOCK_RADAR_MESH_DISCOVERY` | `false` | LAN UDPブロードキャストによるノード自動検出の有効化 |
| `--mesh-port` | `DOCK_RADAR_MESH_PORT` | `9085` | LANピア自動検出ビーコンのUDPポート |
| `--gossip-interval` | `DOCK_RADAR_GOSSIP_INTERVAL` | `5s` | SWIM分散型クラスタGossip Pingの間隔 |
| `--version` | — | — | dock-radarのバージョンを表示して終了 |

---

## 🏛️ アーキテクチャとセキュリティ (Architecture & Security)

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

### セキュリティ保証 (Security Guarantees)
- **トランスポート層暗号化 (TLS)**: すべてのホストインターフェースのSAN検証を含むインメモリECDSA P-256自己署名証明書生成およびカスタムエンタープライズ証明書の適用をサポートします。
- **定数時間認証**: トークン検証は `crypto/subtle.ConstantTimeCompare` を用いて行われ、APIトークンに対するタイミング攻撃を完全に無力化します。
- **詳細なRBAC分離**: 読み取りエンドポイント（システムメトリクス、コンテナ一覧、ログ配信）は `viewer` と `admin` の両方が利用でき、変更操作（再起動、停止、アラート設定）は厳格に `admin` を要求します。
- **ループバックデフォルト制限**: 認証トークンが未設定の場合、状態を変更するエンドポイントはローカルループバックインターフェース（`127.0.0.1`、`::1`、`localhost`）のみに厳密に制限されます。
- **CSRFおよびDNSリバインディング防御**: ブラウザメタデータ（`Sec-Fetch-Site`）および `Origin`/`Referer` ヘッダーを検証し、クロスオリジン攻撃を防ぎます。
- **SSRFおよびメタデータ遮断**: Webhook送信先は厳密なHTTP/HTTPSプロトコルを強制し、改行文字（CRLF）を除外してクラウドメタデータアドレス（`169.254.169.254`、`metadata.google.internal`）への通信を遮断します。
- **パラメータ検証**: すべてのコンテナIDおよび名前は英数字パターン（`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`）で厳格に検証され、パストラバーサルやインジェクションを防止します。
- **レート制限保護**: トークンバケットアルゴリズムにより、コンテナ操作およびアラート制御APIの呼び出しをバースト5回、毎秒1トークン補充に制限します。

---

## 📡 REST & WebSocket API リファレンス

| エンドポイント | メソッド / プロトコル | 必要ロール | 説明 |
| :--- | :---: | :---: | :--- |
| `/metrics` | `GET` | `viewer` | Grafana収集用の標準Prometheusメトリクスエンドポイント |
| `/api/system` | `GET` | `viewer` | ホスト名、OS/Arch、CPUコア数、活動中goroutine数、割り当てRAM、GC回数、稼働時間 |
| `/api/docker` | `GET` | `viewer` | Dockerデーモン接続状態、総コンテナ数、稼働中コンテナ数、詳細情報 |
| `/api/docker/batch` | `POST` | `admin` | コンテナ一括操作：`restart_all`、`stop_all`、`prune` (`{"action":"restart_all","timeout":10}`) |
| `/api/docker/logs` | `WS` / `GET` | `viewer` | リアルタイムWebSocketログフィードまたはJSONスナップショット (`?id=<id>&stream=<stdout\|stderr\|system>&tail=100`) |
| `/api/docker/restart` | `POST` | `admin` | IDまたは名前によるコンテナの安全な再起動 (`{"id":"<name_or_id>","timeout":10}`) |
| `/api/docker/stop` | `POST` | `admin` | 稼働中コンテナの安全な停止 (`{"id":"<name_or_id>","timeout":10}`) |
| `/api/healing/config` | `GET` / `POST` | `viewer` / `admin` | 自動修復ポリシー、ジッター制限、除外ルールの取得・更新 |
| `/api/healing/status` | `GET` | `viewer` | アクティブな修復メトリクス、隔離コンテナ一覧、バックオフ状態 |
| `/api/healing/history`| `GET` | `viewer` | 直近の自己修復イベント履歴ログ (`?limit=50&container=`) |
| `/api/healing/reset`  | `POST` | `admin` | コンテナのサーキットブレーカー隔離を解除しバックオフをリセット |
| `/api/nodes` | `GET` / `POST` / `DELETE` | `viewer` / `admin` | ノードインベントリ一覧、動的ノード登録および登録解除 |
| `/api/nodes/heartbeat` | `POST` | `viewer` | リモートエージェントテレメトリおよびコンテナ同期プッシュエンドポイント |
| `/api/cluster/summary` | `GET` | `viewer` | クラスタ集約メトリクス（総ノード数、オンライン/オフライン、CPU、メモリ、総コンテナ） |
| `/api/cluster/containers` | `GET` | `viewer` | 全クラスタノードにまたがる統合コンテナインベントリ (`?node_id=&state=`) |
| `/api/mesh/discovery` | `GET` / `POST` | `viewer` / `admin` | LAN UDP自動検出状態の取得および手動ビーコン送信 (`POST {"action":"broadcast"}`) |
| `/api/mesh/gossip` | `GET` / `POST` | `viewer` / `none` | クラスタSWIM Gossipメンバーシップ状態およびP2Pメッセージ受信 |
| `/api/audit/export` | `GET` | `viewer` | NDJSONまたはJSON形式での監査証跡ログのエクスポート (`?format=ndjson&limit=2000&action=`) |
| `/api/alerts/config` | `GET` / `POST` | `viewer` / `admin` | アクティブなアラートルール、Webhook宛先、閾値設定の取得・更新 |
| `/api/alerts/events` | `GET` | `viewer` | 直近に発生したインシデントおよびアラート履歴の取得 (`?limit=50`) |
| `/api/alerts/test` | `POST` | `admin` | DiscordまたはSlackへテストWebhookペイロードを即時送信 |
| `/api/auth/status` | `GET` | `none` | TLS状態、リモートアクセスモード、認証要件および現在のロールを返却 |
| `/api/auth/verify` | `POST` | `none` | クライアントBearerトークンを検証し付与されたロールを返却 |
| `/` | `GET` | `none` | 組み込みのシングルページWebダッシュボードを提供 |

---

## 🗺️ ロードマップ (Roadmap)

今後のマイルストーンや新機能の計画については [ROADMAP.md](../../ROADMAP.md) をご覧ください。

---

## 🔒 セキュリティ (Security)

脆弱性の報告手順については [SECURITY.md](../../SECURITY.md) をご参照ください。

---

## 📄 ライセンス (License)

本ソフトウェアは [Apache License 2.0](../../LICENSE) に基づいて公開されています。
