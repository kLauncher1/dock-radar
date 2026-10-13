<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <b>🇨🇳 简体中文</b> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**超轻量级单二进制容器与系统指标监控引擎（内置实时暗色模式 Web 仪表板）**

<sub>由 kLauncher1 打造 · 专为家庭实验室与边缘节点设计的极低资源开销</sub>

</div>

---

## ⚡ 核心亮点

- **单可执行文件部署**: 通过 Go `//go:embed` 技术将 Web 仪表板直接烘焙进二进制文件。无需 Node.js 运行时或独立前端服务器。
- **超低内存占用**: 常驻内存占用低于 **15 MB RAM**，非常适合低配 VPS、树莓派及边缘环境。
- **Docker 套接字直通**: 直接与 `/var/run/docker.sock`（Linux/macOS）或命名管道（Windows）通信，具备弹性的离线后备机制。
- **主机系统遥测**: 实时追踪 CPU 核心、Goroutine、内存分配、垃圾回收（GC）周期和运行时间。
- **暗色毛玻璃拟态 UI**: 高对比度、干净整洁的视觉仪表板，提供实时容器检查、状态标签和实时事件日志。

---

## 🚀 快速上手

### 1. 下载与运行

```bash
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

go run .
```

内置 Web 控制台可立即访问：
👉 **`http://localhost:9080`**

### 2. 编译单二进制可执行文件

```bash
go build -ldflags="-s -w" -o dock-radar .
./dock-radar
```

---

<sub>Copyright © 2026 kLauncher1. Apache-2.0 License.</sub>
