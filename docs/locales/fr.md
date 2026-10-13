<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <b>🇫🇷 Français</b> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**Moniteur ultra-léger de conteneurs et de métriques système en un seul binaire avec tableau de bord web sombre intégré.**

<sub>Conçu par kLauncher1 · Empreinte minimale pour homelabs et serveurs légers.</sub>

</div>

---

## ⚡ Points Forts

- **Déploiement en un Seul Binaire**: Interface web directement intégrée au binaire Go via `//go:embed`. Aucun runtime Node.js ni serveur web externe requis.
- **Empreinte Mémoire Ultra-Faible**: Fonctionne en continu sous **15 Mo de RAM**, idéal pour VPS modestes et Raspberry Pi.
- **Communication Directe Docker**: Dialogue avec `/var/run/docker.sock` ou Named Pipes Windows avec repli hors ligne résilient.
- **Télémétrie Système Hôte**: Suivi en direct des cœurs CPU, goroutines, RAM allouée, cycles GC et uptime.
- **Interface Glassmorphism Sombre**: Tableau de bord haute lisibilité avec statut des conteneurs et flux d’événements en direct.

---

## 🚀 Démarrage Rapide

```bash
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# Exécution directe
go run .

# Compilation binaire autonome
go build -ldflags="-s -w" -o dock-radar .
./dock-radar
```

Tableau de bord web: 👉 **`http://localhost:9080`**

---

<sub>Copyright © 2026 kLauncher1. Apache-2.0 License.</sub>
