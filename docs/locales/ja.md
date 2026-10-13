<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <b>🇯🇵 日本語</b> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**超軽量シングルバイナリ コンテナ＆ホストシステム監視エンジン（リアルタイム ダークモード Web ダッシュボード内蔵）**

<sub>kLauncher1 制作 · ホームラボやエッジノード向け極小リソース設計</sub>

</div>

---

## ⚡ 主な特徴

- **単一バイナリ配布**: Go の `//go:embed` を活用し、Web ダッシュボードをバイナリ内に直接内蔵。Node.js や追加の Web サーバーは不要。
- **超省メモリ動作**: 常時メモリ使用量は **15 MB 未満**。低スペック VPS や Raspberry Pi に最適。
- **Docker ソケット直接通信**: `/var/run/docker.sock` または Windows 名前付きパイプと直接通信。オフライン時も安定したフォールバック。
- **ホストシステムテレメトリ**: リアルタイム CPU コア、Goroutine、メモリ割り当て、GC サイクル、稼働時間を正確に計測。
- **ダークモード グラスモーフィズム UI**: コンテナの状態やイベントログを即座に確認できる高コントラストな Web コンソール。

---

## 🚀 クイックスタート

```bash
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# 直接実行
go run .

# シングルバイナリのビルド
go build -ldflags="-s -w" -o dock-radar .
./dock-radar
```

Web ダッシュボード: 👉 **`http://localhost:9080`**

---

<sub>Copyright © 2026 kLauncher1. Apache-2.0 License.</sub>
