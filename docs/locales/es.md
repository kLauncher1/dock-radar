<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <b>🇪🇸 Español</b><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**Monitor ultraligero de contenedores y métricas del sistema en un único binario con panel web en modo oscuro integrado.**

<sub>Diseñado por kLauncher1 · Sobrecarga mínima para homelabs y nodos edge.</sub>

</div>

---

## ⚡ Aspectos Clave

- **Despliegue en un Solo Binario**: Panel web integrado directamente en el binario Go mediante `//go:embed`. Sin dependencia de Node.js ni servidores externos.
- **Memoria Ultrabaja**: Funciona de forma persistente con **menos de 15 MB de RAM**, ideal para VPS de bajos recursos y Raspberry Pi.
- **Inspección Directa de Docker**: Conexión nativa con `/var/run/docker.sock` o Named Pipes en Windows con modo de respaldo fuera de línea.
- **Telemetría del Sistema Host**: Supervisión en tiempo real de núcleos de CPU, goroutines, RAM asignada, ciclos de GC y tiempo de actividad.
- **Interfaz Glassmorphism en Modo Oscuro**: Panel de control con inspección de contenedores, estados en vivo y registro de eventos.

---

## 🚀 Inicio Rápido

```bash
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# Ejecución directa
go run .

# Compilación de binario único
go build -ldflags="-s -w" -o dock-radar .
./dock-radar
```

Consola web: 👉 **`http://localhost:9080`**

---

<sub>Copyright © 2026 kLauncher1. Apache-2.0 License.</sub>
