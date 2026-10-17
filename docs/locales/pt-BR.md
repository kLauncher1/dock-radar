<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <b>🇧🇷 Português</b> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**Monitor ultraleve de contêineres e métricas de sistema em binário único com painel web escuro integrado.**

<sub>Criado por kLauncher1 · Sobrecarga mínima para homelabs e nós edge.</sub>

</div>

---

## ⚡ Destaques

- **Implantação em Binário Único**: Painel web incorporado diretamente no binário Go via `//go:embed`. Sem dependência de Node.js ou servidores web externos.
- **Consumo de Memória Ultrabaixo**: Opera continuamente abaixo de **15 MB de RAM**, perfeito para VPS modestos e Raspberry Pi.
- **Inspeção Direta do Docker**: Conexão nativa com `/var/run/docker.sock` ou Named Pipes no Windows com fallback offline resiliente.
- **Telemetria do Sistema Host**: Acompanhamento em tempo real de núcleos de CPU, goroutines, RAM alocada, ciclos de GC e uptime.
- **Interface Glassmorphism no Modo Escuro**: Painel visual de alto contraste com status de contêineres e registro de eventos em tempo real.

---

## 🚀 Início Rápido

```bash
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# Execução direta
go run .

# Compilação de binário único
go build -ldflags="-s -w" -o dock-radar .
./dock-radar
```

Painel web: 👉 **`http://localhost:9080`**

---

<sub>Copyright © 2026 kLauncher1. Apache-2.0 License.</sub>
