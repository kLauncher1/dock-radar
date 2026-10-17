<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <b>🇫🇷 Français</b> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**Moniteur ultra-léger de métriques de conteneurs et du système en un binaire unique avec tableau de bord web temps réel en mode sombre.**

[![Release](https://img.shields.io/badge/Release-v2.0.0-38bdf8.svg?style=flat)](https://github.com/kLauncher1/dock-radar/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6%2B-3178C6.svg?style=flat&logo=typescript)](https://www.typescriptlang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Memory Footprint](https://img.shields.io/badge/Memory_Footprint-<15MB-10b981.svg)](#-architecture-et-sécurité-architecture--security)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-démarrage-rapide-quick-start)

<sub>Conçu par **kLauncher1** · Optimisé pour une consommation minimale de ressources sur homelabs, serveurs et nœuds périphériques (edge).</sub>

</div>

---

## ⚡ Points Forts (Highlights)

- **Déploiement en un Fichier Binaire Unique**: Le tableau de bord web est directement intégré dans le binaire Go via la directive `//go:embed`. Aucun environnement Node.js, ressource externe ou serveur web distinct n'est nécessaire.
- **Empreinte Mémoire Ultra-Réduite**: Fonctionne en continu avec **moins de 15 Mo de RAM** grâce à des mémoires tampons circulaires à capacité bornée, convenant parfaitement aux VPS d'entrée de gamme, Raspberry Pi et configurations homelab.
- **Télémétrie eBPF Adaptative au Niveau du Noyau et Sécurité Comportementale**: Traqueur de flux de sockets basé uniquement sur la bibliothèque standard et inspecteur Linux `/proc/net/tcp` mesurant en temps réel les connexions TCP/UDP, les débits en octets et la latence aller-retour (RTT). Le moteur de sécurité comportementale surveille les appels système des conteneurs pour détecter l'exécution imprévue d'un shell (`execve`), l'élévation de privilèges (`setuid`), l'inspection mémoire (`ptrace`), l'accès aux identifiants hôtes (`/etc/shadow`), le détournement du socket Docker et les connexions de minage, avec affichage en direct et flux d'incidents.
- **Stockage Éphémère Distribué des Journaux et Décharge vers S3**: Compression en mémoire des journaux de conteneurs en fragments gzip (`.gz`) avec sommes de contrôle cryptographiques SHA-256 et écriture atomique sur disque. Un module d'exportation asynchrone transmet les fragments vers du stockage compatible S3 (AWS S3, MinIO, Cloudflare R2) via un signataire AWS SigV4 sans dépendance externe, avec gestion des quotas locaux, rotation par âge et explorateur de fragments avec téléchargement direct.
- **Redémarrages Échelonnés Sans Interruption et Vidange du Trafic (Zero-Downtime Rolling Restarts)**: Orchestration séquentielle du redémarrage des conteneurs par réplicas, stacks Compose ou groupes d'étiquettes. Intègre une vidange progressive du trafic en cours avec délais d'expiration configurables, notification webhook vers les proxys inverses, sondage de préparation en plusieurs étapes (état Docker, contrôle de santé, points d'accès `/healthz`, période de grâce) et déclencheurs d'annulation automatique en cas de défaillance.
- **Maillage de Nœuds Dynamique et Découverte par Gossip**: Détection automatique sur réseau local via diffusion UDP (port 9085) couplée au protocole léger de gossip SWIM. Comprend des pings/acks directs aléatoires, des pings d'assistance indirects ($k=3$), des temporisateurs de suspicion, la réfutation d'incarnation et un consensus décentralisé de santé affiché dans le tableau de bord.
- **Détection Prédictive des Anomalies et Radar d'Épuisement OOM**: Analyse de régression linéaire par moindres carrés ordinaires (OLS) en temps réel anticipant la pente de saturation mémoire ($m$), l'ordonnée à l'origine ($c$) et le délai avant épuisement (TTE). Envoi d'alertes webhook préventives avant l'intervention du tueur OOM du noyau, complété par des jauges de compte à rebours visuelles.
- **Moteur d'Auto-Guérison Autonome (Self-Healing)**: Exécution de règles automatisées de restauration lors des arrêts pour dépassement de mémoire (`exit 137`) ou d'états d'instabilité, protégées par un recul exponentiel avec gigue, des seuils de mise en quarantaine par coupe-circuit et des métriques Prometheus.
- **Visualiseur de Topologie et Stacks Docker Compose**: Regroupement automatique des conteneurs selon les étiquettes `com.docker.compose.project` avec graphiques de dépendances SVG interactifs. Détection des strates d'architecture (base de données, cache, file d'attente, passerelle, exécutant) et contrôle de cycle de vie complet de la stack (redémarrage, arrêt, recréation).
- **Terminal de Conteneur Interactif Intégré au Navigateur (Exec)**: Terminal bidirectionnel complet via WebSocket (`/api/docker/exec`) restituant fidèlement les séquences d'échappement VT100 / ANSI (256 couleurs), appliquant des règles d'accès en lecture seule et terminant automatiquement les sessions inactives.
- **Maillage d'Agents Multi-Hôtes et Concentrateur Distribué**: Surveillance en direct des conteneurs répartis sur plusieurs serveurs. Prise en charge de l'enregistrement dynamique des nœuds, du sondage de santé des pairs, du suivi de la latence RTT et de l'agrégation globale des métriques.
- **Exportateur de Métriques Standard pour Prometheus**: Point d'accès natif `/metrics` exposant les données de l'hôte, des conteneurs, des nœuds du maillage, des alertes et des pistes d'audit au format d'exposition Prometheus pour Grafana.
- **Gestion Groupée des Conteneurs**: Commandes synchronisées via interface ou API (`restart_all`, `stop_all`) et purge automatique des conteneurs inactifs (`prune`).
- **Journal d'Audit Thread-Safe**: Tampon circulaire d'une capacité de 2 000 entrées consignant les actions de sécurité et d'administration, avec exportation en flux NDJSON et JSON (`/api/audit/export`).
- **Chiffrement Automatique des Communications (TLS)**: Moteur de certificats générant en mémoire des certificats auto-signés ECDSA P-256 avec SAN pour localhost et les interfaces réseau locales. Prise en charge intégrale de certificats personnalisés via arguments CLI et variables d'environnement.
- **Authentification par Jeton Bearer et Contrôle RBAC**: Séparation stricte entre les rôles `admin` (gestion complète du cycle de vie et alertes) et `viewer` (consultation en lecture seule), avec comparaison à temps constant (`subtle.ConstantTimeCompare`) pour parer aux attaques temporelles.
- **Notifications Automatisées par Webhook**: Alertes immédiates envoyées vers Discord (messages enrichis avec codes couleur) et Slack lors d'un arrêt imprévu, d'un crash ou d'une boucle de redémarrages.
- **Détection des Flottements et Fréquence de Pannes (Flapping)**: Surveillance par fenêtre glissante repérant les cycles de redémarrage anormalement rapides avant toute rupture de service globale.
- **Contrôle des Seuils de Ressources de l'Hôte**: Définition de limites de saturation processeur et mémoire avec déduplication des alertes et fenêtres de temporisation.
- **Diffusion des Journaux en Temps Réel**: Flux continu WebSocket conforme RFC 6455 (`/api/docker/logs`) avec démultiplexage natif des sorties stdout/stderr de Docker et solution de repli par instantanés REST JSON.
- **Contrôle du Socket Docker et Cycle de Vie**: Diagnostic des conteneurs actifs avec boîtes de dialogue de confirmation pour les arrêts, relances et suppressions groupées.
- **Télémétrie du Système Hôte**: Suivi en continu du nombre de cœurs processeur, des goroutines, de la mémoire vive allouée, des passages du ramasse-miettes (GC) et de la durée d'activité.
- **Compatibilité Multi-Plateforme**: Binaires testés et validés pour Linux (amd64, arm64), macOS (amd64, arm64 Apple Silicon) et Windows (amd64).

---

## 🚀 Démarrage Rapide (Quick Start)

### 1. Téléchargement et Exécution (Binaire Autonome)

```bash
# Cloner le dépôt
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# Lancer directement avec Go (port HTTP par défaut : 9080)
go run .
```

La console web intégrée est immédiatement accessible sur :
👉 **`http://localhost:9080`**

### 2. Exécution avec TLS et Authentification (Mode Sécurisé de Production)

```bash
# Activer le TLS auto-signé et définir les jetons d'accès
go run . --tls --admin-token="mon-jeton-admin-secret" --viewer-token="mon-jeton-lecture-seule"
```

Accès à la console sécurisée :
👉 **`https://localhost:9080`**

### 3. Compilation d'un Binaire Unique

```bash
# Compile un exécutable léger dépourvu de symboles de débogage
go build -ldflags="-s -w" -o dock-radar .

# Consulter l'aide du binaire
./dock-radar --help
```

### 4. Options de Configuration et Variables d'Environnement

| Option CLI | Variable d'Environnement | Valeur par Défaut | Description |
| :--- | :--- | :--- | :--- |
| `--port` | `PORT` | `9080` | Port TCP d'écoute pour l'interface et l'API |
| `--tls` | `DOCK_RADAR_TLS` | `false` | Active le protocole HTTPS avec certificat automatique ou dédié |
| `--tls-cert` | `DOCK_RADAR_TLS_CERT` | `""` | Chemin d'accès au certificat TLS au format PEM |
| `--tls-key` | `DOCK_RADAR_TLS_KEY` | `""` | Chemin d'accès à la clé privée TLS au format PEM |
| `--admin-token` | `DOCK_RADAR_ADMIN_TOKEN` | `""` | Jeton Bearer conférant un contrôle d'administration absolu |
| `--viewer-token` | `DOCK_RADAR_VIEWER_TOKEN`| `""` | Jeton Bearer autorisant la consultation des métriques en lecture seule |
| `--allow-remote` | `DOCK_RADAR_ALLOW_REMOTE`| `false` | Autorise les connexions réseau externes sans restriction locale |
| `--nodes` | `DOCK_RADAR_NODES` | `""` | Liste de nœuds dock-radar distants à agréger (séparés par des virgules) |
| `--node-name` | `DOCK_RADAR_NODE_NAME` | `hostname` | Nom d'identification affiché pour ce nœud sur le tableau de bord |
| `--mesh-discovery` | `DOCK_RADAR_MESH_DISCOVERY` | `false` | Active la découverte automatique des pairs locaux par diffusion UDP |
| `--mesh-port` | `DOCK_RADAR_MESH_PORT` | `9085` | Port UDP pour les balises de découverte sur le réseau local |
| `--gossip-interval` | `DOCK_RADAR_GOSSIP_INTERVAL` | `5s` | Intervalle des pings de gossip du protocole SWIM |
| `--version` | — | — | Affiche la version de dock-radar puis s'arrête |

---

## 🏛️ Architecture et Sécurité (Architecture & Security)

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

### Garanties de Sécurité (Security Guarantees)
- **Chiffrement de Bout en Bout (TLS)**: Création dynamique en mémoire de certificats ECDSA P-256 avec validation SAN pour les adresses locales, ou importation de certificats d'entreprise.
- **Vérification d'Accès à Temps Constant**: La validation des jetons recourt à `crypto/subtle.ConstantTimeCompare`, neutralisant les attaques temporelles par canal auxiliaire.
- **Compartimentation des Rôles (RBAC)**: Les points d'accès de lecture sont accessibles aux statuts `viewer` et `admin`, tandis que les actions modificatrices nécessitent impérativement le rôle `admin`.
- **Restriction Locale par Défaut**: En l'absence de jeton de sécurité, les requêtes altérant la configuration sont cantonnées à l'interface de bouclage (`127.0.0.1`, `::1`, `localhost`).
- **Protection Anti-CSRF et Re-liaison DNS**: Contrôle des métadonnées du navigateur (`Sec-Fetch-Site`) et des en-têtes `Origin`/`Referer` afin de bloquer les requêtes inter-origines non autorisées.
- **Filtrage SSRF et Verrouillage des Métadonnées**: Les cibles de webhooks imposent des protocoles HTTP/HTTPS stricts, éliminent les caractères de contrôle (CRLF) et bloquent catégoriquement les passerelles de métadonnées de cloud public (`169.254.169.254`, `metadata.google.internal`).
- **Contrôle des Paramètres d'Entrée**: Tous les identifiants et désignations de conteneurs sont validés selon le modèle alphanumérique `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$` pour prévenir les traversées de répertoires.
- **Régulation de Débit (Rate Limiting)**: Un algorithme de seau à jetons autorise des salves de 5 requêtes avec réapprovisionnement à raison d'un jeton par seconde.

---

## 📡 Référence des API REST et WebSocket

| Point d'Accès | Méthode / Protocole | Rôle Requis | Description |
| :--- | :---: | :---: | :--- |
| `/metrics` | `GET` | `viewer` | Métriques standard au format Prometheus pour supervision avec Grafana |
| `/api/system` | `GET` | `viewer` | Nom d'hôte, système/architecture, cœurs CPU, goroutines, RAM (Mo), passages GC et durée de service |
| `/api/docker` | `GET` | `viewer` | État du démon Docker, décompte global et détaillé des conteneurs |
| `/api/docker/batch` | `POST` | `admin` | Actions en lot : `restart_all`, `stop_all`, `prune` (`{"action":"restart_all","timeout":10}`) |
| `/api/docker/logs` | `WS` / `GET` | `viewer` | Flux WebSocket en direct ou instantané JSON (`?id=<id>&tail=100`) |
| `/api/docker/restart` | `POST` | `admin` | Redémarrage ordonné d'un conteneur par son nom ou son ID (`{"id":"<id>","timeout":10}`) |
| `/api/docker/stop` | `POST` | `admin` | Arrêt contrôlé d'un conteneur en cours d'exécution (`{"id":"<id>","timeout":10}`) |
| `/api/healing/config` | `GET` / `POST` | `viewer` / `admin` | Consultation et mise à jour de la politique d'auto-réparation et exclusions |
| `/api/healing/status` | `GET` | `viewer` | Métriques de réparation, liste des conteneurs en quarantaine et temporisations |
| `/api/healing/history`| `GET` | `viewer` | Journal historique des opérations d'auto-guérison récentes (`?limit=50`) |
| `/api/healing/reset`  | `POST` | `admin` | Réinitialise le coupe-circuit et remet à zéro les compteurs de mise en quarantaine |
| `/api/nodes` | `GET` / `POST` / `DELETE` | `viewer` / `admin` | Répertoire des nœuds, enregistrement dynamique et retrait de membres |
| `/api/nodes/heartbeat` | `POST` | `viewer` | Point de collecte de télémétrie et synchronisation des agents distants |
| `/api/cluster/summary` | `GET` | `viewer` | Vue synthétique du cluster (nœuds connectés, processeur, mémoire, total conteneurs) |
| `/api/cluster/containers` | `GET` | `viewer` | Inventaire centralisé des conteneurs sur l'ensemble des nœuds (`?node_id=&state=`) |
| `/api/mesh/discovery` | `GET` / `POST` | `viewer` / `admin` | État de la découverte locale par UDP et déclenchement manuel (`POST {"action":"broadcast"}`) |
| `/api/mesh/gossip` | `GET` / `POST` | `viewer` / `none` | Adhésion au maillage SWIM et réception de messages de gossip P2P |
| `/api/audit/export` | `GET` | `viewer` | Exportation de la trace d'audit aux formats NDJSON ou JSON (`?format=ndjson&limit=2000`) |
| `/api/alerts/config` | `GET` / `POST` | `viewer` / `admin` | Gestion des directives d'alerte, cibles de webhook et seuils limites |
| `/api/alerts/events` | `GET` | `viewer` | Historique des incidents récents et déclenchements d'alertes (`?limit=50`) |
| `/api/alerts/test` | `POST` | `admin` | Expédition immédiate d'un message de test vers Discord ou Slack |
| `/api/auth/status` | `GET` | `none` | Indique l'état du chiffrement TLS, le mode d'accès distant et les prérogatives actives |
| `/api/auth/verify` | `POST` | `none` | Vérifie la validité d'un jeton Bearer et renvoie le rôle correspondant |
| `/` | `GET` | `none` | Distribution de l'application web monopage intégrée |

---

## 🗺️ Feuille de Route (Roadmap)

Consultez [ROADMAP.md](../../ROADMAP.md) pour découvrir les prochaines étapes, fonctionnalités et versions programmées.

---

## 🔒 Sécurité (Security)

Pour la déclaration responsable de vulnérabilités, veuillez vous reporter à [SECURITY.md](../../SECURITY.md).

---

## 📄 Licence (License)

Ce projet est distribué sous licence [Apache License 2.0](../../LICENSE).
