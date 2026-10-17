<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <b>🇪🇸 Español</b><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**Monitor ultraligero de métricas de contenedores y del sistema en un único binario con panel web integrado en tiempo real y modo oscuro.**

[![Release](https://img.shields.io/badge/Release-v2.0.0-38bdf8.svg?style=flat)](https://github.com/kLauncher1/dock-radar/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6%2B-3178C6.svg?style=flat&logo=typescript)](https://www.typescriptlang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Memory Footprint](https://img.shields.io/badge/Memory_Footprint-<15MB-10b981.svg)](#-arquitectura-y-seguridad-architecture--security)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-inicio-rápido-quick-start)

<sub>Creado por **kLauncher1** · Diseñado para un consumo mínimo de recursos en homelabs, servidores y nodos edge.</sub>

</div>

---

## ⚡ Aspectos Destacados (Highlights)

- **Despliegue en un Único Binario Ejecutable**: El panel de control web está integrado directamente en el binario de Go mediante `//go:embed`. No requiere entorno de ejecución Node.js, recursos externos ni servidores web independientes.
- **Consumo de Memoria Ultrarreducido**: Funciona de forma continua con **menos de 15 MB de RAM** gracias a búferes circulares de capacidad acotada, lo que resulta idóneo para VPS de gama baja, Raspberry Pi y entornos de laboratorio doméstico.
- **Telemetría eBPF Adaptativa y Motor de Seguridad por Comportamiento**: Rastreador de flujos de sockets basado exclusivamente en la biblioteca estándar e inspector de Linux `/proc/net/tcp` para medir conexiones TCP/UDP, rendimiento en bytes y latencia RTT en tiempo real. Su motor de seguridad supervisa las llamadas al sistema e incorpora reglas para detectar ejecuciones de shell imprevistas (`execve`), escalada de privilegios (`setuid`), inspección de memoria (`ptrace`), acceso a credenciales del host (`/etc/shadow`), abusos del socket de Docker y conexiones a redes de minería, junto con un monitor visual de flujos y panel de incidentes.
- **Almacenamiento Efímero Distribuido y Descarga a S3**: Comprime los registros de contenedores en memoria en bloques gzip (`.gz`) con sumas de comprobación SHA-256 y escritura atómica en disco. Su descargador asíncrono transmite los bloques a almacenamiento compatible con S3 (AWS S3, MinIO, Cloudflare R2) mediante un firmante AWS SigV4 sin dependencias externas. Incorpora límites de capacidad local, purga por antigüedad y un explorador de bloques con descarga directa.
- **Reinicios Continuos sin Interrupción y Vaciado de Tráfico (Zero-Downtime Rolling Restarts)**: Orquesta reinicios secuenciales de réplicas, pilas de Compose o grupos de etiquetas. Incluye vaciado ordenado del tráfico en curso con tiempos de espera configurables, notificaciones por webhook a proxies inversos, sondeo de preparación en varias etapas (estado de Docker, comprobación de salud, endpoints `/healthz`, margen de gracia) y aborto automático ante fallos en cascada.
- **Malla Dinámica Multinodo y Descubrimiento por Gossip**: Detección automática por difusión UDP en red local (puerto 9085) combinada con el protocolo de gossip SWIM. Dispone de pings directos aleatorios, pings indirectos de asistencia ($k=3$), temporizadores de sospecha, refutación de encarnación y consenso descentralizado de salud reflejado en tarjetas multihost en el panel web.
- **Detección Predictiva de Anomalías y Radar de Agotamiento OOM**: Análisis de regresión lineal OLS en tiempo real para pronosticar la pendiente de saturación de memoria ($m$), punto de corte ($c$) y tiempo estimado hasta el agotamiento (TTE). Envía alertas por webhook antes de que el kernel ejecute el OOM killer e incluye indicadores de cuenta regresiva en el panel.
- **Motor Autónomo de Autorreparación (Self-Healing)**: Ejecuta directivas automáticas de recuperación tras caídas por falta de memoria (`exit 137`) o estados de aleteo persistentes, protegido mediante retroceso exponencial con fluctuación aleatoria, umbrales de aislamiento y métricas para Prometheus.
- **Visualizador de Topología y Pilas de Docker Compose**: Agrupa contenedores a partir de la etiqueta `com.docker.compose.project` y renderiza gráficos SVG interactivos de dependencias. Identifica niveles arquitectónicos (base de datos, caché, colas, pasarelas, trabajadores) y permite operaciones de ciclo de vida completas (reiniciar, detener, recrear).
- **Terminal Interactivo en Navegador (Exec)**: Terminal bidireccional sobre WebSocket (`/api/docker/exec`) con renderizado completo de secuencias de escape VT100 / ANSI (256 colores), control de acceso en modo solo lectura y cierre por inactividad.
- **Malla de Agentes Multihost y Concentrador Remoto**: Monitorización centralizada de contenedores en arquitecturas distribuidas. Soporta registro dinámico de nodos, sondeo de disponibilidad, seguimiento de latencia y agregación de telemetría multinodo.
- **Exportador Estándar de Métricas para Prometheus**: Endpoint nativo `/metrics` que expone estadísticas del host, contenedores, nodos de la malla, alertas y auditoría con formato compatible para su ingesta en Grafana.
- **Operaciones de Lote en Contenedores**: Control simultáneo mediante API o panel para acciones globales (`restart_all`, `stop_all`) y limpieza automática de contenedores inactivos (`prune`).
- **Registro Seguro de Auditoría (Audit Trail)**: Búfer circular de tamaño fijo que almacena hasta 2.000 acciones administrativas y de seguridad, exportable en formatos NDJSON y JSON (`/api/audit/export`).
- **Cifrado de Transporte TLS Automatizado**: Motor TLS en memoria que genera certificados autofirmados ECDSA P-256 con nombres alternativos de sujeto (SAN) para localhost e interfaces de red. Admite la configuración de certificados personalizados vía parámetros o variables de entorno.
- **Autenticación Bearer y Control de Acceso por Roles (RBAC)**: Distingue los perfiles `admin` (control completo del ciclo de vida y gestión de alertas) y `viewer` (lectura de telemetría y registros), aplicando comparaciones en tiempo constante (`subtle.ConstantTimeCompare`) para evitar ataques de canal lateral.
- **Notificaciones Automáticas por Webhook**: Alertas inmediatas hacia Discord (con formato enriquecido) y Slack ante salidas inesperadas, caídas o bucles continuos de reinicio.
- **Detección de Aleteo y Frecuencia de Fallos (Flapping)**: Supervisión con ventana deslizante para detectar secuencias rápidas de reinicios antes de que provoquen una indisponibilidad general.
- **Supervisión de Umbrales en el Host**: Control de consumo de CPU y memoria con desduplicación de alertas y periodos de enfriamiento.
- **Transmisión de Registros en Tiempo Real**: Conexión WebSocket RFC 6455 (`/api/docker/logs`) con demultiplexación de salidas stdout/stderr de Docker y alternativa en JSON para consultas REST.
- **Inspección del Socket de Docker y Control de Operaciones**: Diagnostica contenedores activos y ofrece controles seguros de reinicio, parada y eliminación con diálogo de confirmación.
- **Telemetría del Sistema Host**: Supervisión en tiempo real de núcleos de CPU, goroutines, memoria RAM asignada, recolecciones de basura (GC) y tiempo de actividad.
- **Matriz de Binarios Multiplataforma**: Compilado y probado para Linux (amd64, arm64), macOS (amd64, arm64 Apple Silicon) y Windows (amd64).

---

## 🚀 Inicio Rápido (Quick Start)

### 1. Descarga y Ejecución (Binario Independiente)

```bash
# Clonar el repositorio
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# Ejecutar directamente mediante Go (puerto HTTP predeterminado: 9080)
go run .
```

El panel de control web estará disponible de inmediato en:
👉 **`http://localhost:9080`**

### 2. Ejecutar con TLS y Autenticación (Modo Seguro para Producción)

```bash
# Habilitar TLS autofirmado y configurar tokens de acceso
go run . --tls --admin-token="mi-token-secreto-admin" --viewer-token="mi-token-de-lectura"
```

Acceso al panel seguro:
👉 **`https://localhost:9080`**

### 3. Compilar en un Único Binario

```bash
# Compila un ejecutable compacto sin símbolos de depuración
go build -ldflags="-s -w" -o dock-radar .

# Consultar opciones del binario
./dock-radar --help
```

### 4. Opciones de Configuración y Variables de Entorno

| Parámetro CLI | Variable de Entorno | Valor por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--port` | `PORT` | `9080` | Puerto TCP de escucha para el panel y la API |
| `--tls` | `DOCK_RADAR_TLS` | `false` | Activa HTTPS con certificados automáticos o propios |
| `--tls-cert` | `DOCK_RADAR_TLS_CERT` | `""` | Ruta al archivo PEM del certificado TLS |
| `--tls-key` | `DOCK_RADAR_TLS_KEY` | `""` | Ruta al archivo PEM de la clave privada TLS |
| `--admin-token` | `DOCK_RADAR_ADMIN_TOKEN` | `""` | Token Bearer con permisos completos de administración |
| `--viewer-token` | `DOCK_RADAR_VIEWER_TOKEN`| `""` | Token Bearer con acceso de solo lectura |
| `--allow-remote` | `DOCK_RADAR_ALLOW_REMOTE`| `false` | Permite peticiones externas sin restricción de loopback |
| `--nodes` | `DOCK_RADAR_NODES` | `""` | Nodos remotos de dock-radar a agregar (separados por coma) |
| `--node-name` | `DOCK_RADAR_NODE_NAME` | `hostname` | Nombre identificador de este nodo en el panel |
| `--mesh-discovery` | `DOCK_RADAR_MESH_DISCOVERY` | `false` | Habilita el descubrimiento automático por difusión UDP |
| `--mesh-port` | `DOCK_RADAR_MESH_PORT` | `9085` | Puerto UDP para balizas de descubrimiento en la red local |
| `--gossip-interval` | `DOCK_RADAR_GOSSIP_INTERVAL` | `5s` | Frecuencia de los pings de gossip en el clúster SWIM |
| `--version` | — | — | Muestra la versión del programa y finaliza |

---

## 🏛️ Arquitectura y Seguridad (Architecture & Security)

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

### Garantías de Seguridad (Security Guarantees)
- **Cifrado en Tránsito (TLS)**: Generación dinámica de certificados ECDSA P-256 con soporte SAN para interfaces locales y compatibilidad con certificados comerciales.
- **Autenticación en Tiempo Constante**: La comprobación de tokens utiliza `crypto/subtle.ConstantTimeCompare`, evitando vulnerabilidades por análisis temporal.
- **Segmentación RBAC Estricta**: Las rutas de consulta están abiertas a los roles `viewer` y `admin`, mientras que las operaciones con impacto en el estado exigen credenciales de `admin`.
- **Restricción a Loopback por Defecto**: Si no se definen tokens de seguridad, los endpoints de modificación quedan estrictamente limitados a la interfaz local (`127.0.0.1`, `::1`, `localhost`).
- **Defensa ante CSRF y DNS Rebinding**: Verificación de metadatos del navegador (`Sec-Fetch-Site`) y de cabeceras `Origin`/`Referer` para bloquear ataques de origen cruzado.
- **Prevención de SSRF y Protección de Metadatos**: Los destinos de webhooks exigen esquemas HTTP/HTTPS, sanean saltos de línea (CRLF) y descartan accesos a direcciones de metadatos en nubes públicas (`169.254.169.254`, `metadata.google.internal`).
- **Validación Estricta de Parámetros**: Los identificadores y nombres de contenedores deben coincidir con la expresión regular `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`, evitando saltos de directorio e inyecciones en el socket.
- **Límites de Petición por Token Bucket**: Mecanismo de limitación de tasa que admite ráfagas de hasta 5 operaciones con recarga de 1 token por segundo.

---

## 📡 Referencia de la API REST y WebSocket

| Endpoint | Método / Protocolo | Rol Requerido | Descripción |
| :--- | :---: | :---: | :--- |
| `/metrics` | `GET` | `viewer` | Métricas en formato estándar de Prometheus para ingesta en Grafana |
| `/api/system` | `GET` | `viewer` | Nombre del host, arquitectura, núcleos de CPU, goroutines, RAM (MB), GC y tiempo activo |
| `/api/docker` | `GET` | `viewer` | Estado de conexión al daemon de Docker, desglose de contenedores y detalle de estados |
| `/api/docker/batch` | `POST` | `admin` | Acciones colectivas: `restart_all`, `stop_all`, `prune` (`{"action":"restart_all","timeout":10}`) |
| `/api/docker/logs` | `WS` / `GET` | `viewer` | Conexión WebSocket para registros en tiempo real o captura JSON (`?id=<id>&tail=100`) |
| `/api/docker/restart` | `POST` | `admin` | Reinicio seguro por nombre o ID (`{"id":"<nombre_o_id>","timeout":10}`) |
| `/api/docker/stop` | `POST` | `admin` | Detención segura de un contenedor (`{"id":"<nombre_o_id>","timeout":10}`) |
| `/api/healing/config` | `GET` / `POST` | `viewer` / `admin` | Consulta o modifica la política de autorreparación y exclusiones |
| `/api/healing/status` | `GET` | `viewer` | Estadísticas del motor de reparación, contenedores aislados y demoras |
| `/api/healing/history`| `GET` | `viewer` | Registro cronológico de acciones de reparación ejecutadas (`?limit=50`) |
| `/api/healing/reset`  | `POST` | `admin` | Levanta el aislamiento por fusible y restaura los contadores de espera |
| `/api/nodes` | `GET` / `POST` / `DELETE` | `viewer` / `admin` | Inventario de nodos del clúster, alta y baja dinámica |
| `/api/nodes/heartbeat` | `POST` | `viewer` | Recepción de señales de vida y telemetría de agentes remotos |
| `/api/cluster/summary` | `GET` | `viewer` | Consolidado del clúster (nodos activos/inactivos, CPU, memoria, totales) |
| `/api/cluster/containers` | `GET` | `viewer` | Listado unificado de contenedores en toda la topología (`?node_id=&state=`) |
| `/api/mesh/discovery` | `GET` / `POST` | `viewer` / `admin` | Diagnóstico del descubrimiento UDP local y emisión forzada (`POST {"action":"broadcast"}`) |
| `/api/mesh/gossip` | `GET` / `POST` | `viewer` / `none` | Estado de membresía en la malla SWIM e ingesta de mensajes de gossip |
| `/api/audit/export` | `GET` | `viewer` | Exporta la traza de auditoría en formato NDJSON o JSON (`?format=ndjson&limit=2000`) |
| `/api/alerts/config` | `GET` / `POST` | `viewer` / `admin` | Configuración de directivas de alerta, destinos de webhook y umbrales |
| `/api/alerts/events` | `GET` | `viewer` | Historial reciente de incidencias y alertas disparadas (`?limit=50`) |
| `/api/alerts/test` | `POST` | `admin` | Envío de una carga útil de prueba a Discord o Slack |
| `/api/auth/status` | `GET` | `none` | Retorna el estado de TLS, modo de conexión y permisos del llamante |
| `/api/auth/verify` | `POST` | `none` | Valida un token Bearer e indica el nivel de acceso asignado |
| `/` | `GET` | `none` | Servidor para la interfaz web de página única integrada |

---

## 🗺️ Hoja de Ruta (Roadmap)

Consulte [ROADMAP.md](../../ROADMAP.md) para conocer las etapas planificadas, nuevas funciones y el historial de versiones.

---

## 🔒 Seguridad (Security)

Para coordinar la notificación y reporte de vulnerabilidades, consulte [SECURITY.md](../../SECURITY.md).

---

## 📄 Licencia (License)

Distribuido bajo los términos de la licencia [Apache License 2.0](../../LICENSE).
