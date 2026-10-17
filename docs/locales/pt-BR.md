<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <a href="./ko.md">🇰🇷 한국어</a> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <b>🇧🇷 Português</b> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**Monitor ultraleve de métricas de contêineres e do sistema em binário único com painel web integrado em tempo real e modo escuro.**

[![Release](https://img.shields.io/badge/Release-v2.0.0-38bdf8.svg?style=flat)](https://github.com/kLauncher1/dock-radar/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat&logo=go)](https://golang.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6%2B-3178C6.svg?style=flat&logo=typescript)](https://www.typescriptlang.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Memory Footprint](https://img.shields.io/badge/Memory_Footprint-<15MB-10b981.svg)](#-arquitetura-e-segurança-architecture--security)
[![Zero Dependency](https://img.shields.io/badge/Zero--Dependency-Self--Contained-38bdf8.svg)](#-início-rápido-quick-start)

<sub>Desenvolvido por **kLauncher1** · Projetado para consumo mínimo de recursos em homelabs, servidores e nós de borda (edge).</sub>

</div>

---

## ⚡ Destaques (Highlights)

- **Implantação em Binário Executável Único**: O painel web é incorporado diretamente no executável Go via diretiva `//go:embed`. Não requer runtime Node.js, arquivos estáticos externos ou servidores web apartados.
- **Pegada de Memória Ultrarreduzida**: Opera continuamente com **menos de 15 MB de RAM** utilizando buffers circulares de capacidade delimitada, ideal para VPS de entrada, Raspberry Pi e ambientes homelab.
- **Telemetria eBPF Adaptativa no Kernel e Motor de Segurança Comportamental**: Rastreador de fluxos de socket baseado puramente na biblioteca padrão e inspetor Linux `/proc/net/tcp` para mensurar conexões TCP/UDP, taxa de transferência em bytes e latência RTT em tempo real. O motor de segurança analisa chamadas de sistema e detecta execuções de shell anômalas (`execve`), escalonamento de privilégios (`setuid`), inspeção de memória (`ptrace`), acesso a credenciais sensíveis (`/etc/shadow`), abuso do socket do Docker e conexões de mineração, acompanhado de monitor visual de fluxos e feed de incidentes.
- **Armazenamento Efêmero Distribuído de Logs e Despejo para S3**: Comprime logs de contêineres em blocos gzip (`.gz`) com hashes criptográficos SHA-256 e gravação atômica em disco. Um descarregador assíncrono envia os blocos para armazenamento compatível com S3 (AWS S3, MinIO, Cloudflare R2) usando um assinador AWS SigV4 nativo. Inclui limites de disco local, expiração por idade e explorador de blocos com download direto.
- **Reinicializações Contínuas sem Interrupção e Drenagem de Tráfego (Zero-Downtime Rolling Restarts)**: Orquestra reinicializações ordenadas de contêineres em réplicas, stacks Compose ou grupos de rótulos. Incorpora drenagem progressiva do tráfego em andamento com tempos de espera configuráveis, notificações via webhook para proxies reversos, sondagem de prontidão em múltiplos estágios (estado Docker, checagem de saúde, endpoints `/healthz`, janela de tolerância) e abortamento automático em falhas cascata.
- **Malha Dinâmica Multinó e Descoberta por Gossip**: Detecção automática por difusão UDP em rede local (porta 9085) combinada com o protocolo SWIM Gossip. Oferece pings diretos aleatórios, pings indiretos de auxílio ($k=3$), temporizadores de suspeita, contestação de encarnações e consenso descentralizado de saúde exibido em cartões multinó no painel.
- **Detecção Preditiva de Anomalias e Radar de Esgotamento OOM**: Análise de regressão linear por mínimos quadrados ordinários (OLS) em tempo real calculando a inclinação de saturação de memória ($m$), intercepto ($c$) e tempo estimado até o esgotamento (TTE). Dispara alertas preventivos via webhook antes que o kernel execute o OOM Killer, com medidores regressivos visuais no painel.
- **Motor Autônomo de Auto-Recuperação (Self-Healing)**: Regras automatizadas de restauração acionadas após paradas por falta de memória (`exit 137`) ou instabilidade contínua (flapping), protegidas por recuo exponencial com variação aleatória (jitter), limites de quarentena por disjuntor e métricas para Prometheus.
- **Visualizador de Topologia e Stacks Docker Compose**: Agrupa contêineres pelo rótulo `com.docker.compose.project` exibindo grafos de dependência interativos em SVG. Identifica camadas de arquitetura (banco de dados, cache, filas, gateways, workers) e executa ações de ciclo de vida completas (reiniciar, parar, recriar).
- **Terminal Interativo Integrado ao Navegador (Exec)**: Terminal bidirecional completo sobre WebSocket (`/api/docker/exec`) com emulação fiel de sequências VT100 / ANSI (256 cores), imposição de modo somente leitura e encerramento automático por inatividade.
- **Malha de Agentes Multihost e Agregador Distribuído**: Monitoramento centralizado de contêineres em múltiplos servidores. Suporta cadastro dinâmico de nós, testes de disponibilidade, registro de latência RTT e unificação de métricas.
- **Exportador Padronizado de Métricas Prometheus**: Rota nativa `/metrics` compatível com o formato de exposição do Prometheus para ingestão direta no Grafana.
- **Operações em Lote de Contêineres**: Comandos sincronizados via interface ou API (`restart_all`, `stop_all`) e faxina segura de contêineres inativos (`prune`).
- **Trilha de Auditoria Segura para Concorrência**: Buffer circular para até 2.000 registros de eventos administrativos e de segurança com exportação em NDJSON e JSON (`/api/audit/export`).
- **Criptografia Automática de Transporte (TLS)**: Gerador interno de certificados ECDSA P-256 autoassinados com suporte a SAN para interfaces locais e suporte completo a certificados corporativos personalizados via linha de comando ou variáveis de ambiente.
- **Autenticação por Token Bearer e Controle de Acesso RBAC**: Separação clara entre os papéis `admin` (controle irrestrito e configuração de alertas) e `viewer` (apenas consulta), com comparação de tokens em tempo constante (`subtle.ConstantTimeCompare`) para impedir ataques de canal lateral.
- **Alertas Automáticos via Webhook**: Notificações instantâneas enviadas ao Discord (com cores de destaque) e Slack em caso de interrupções inesperadas, falhas ou loops de reinicialização.
- **Monitoramento de Flapping e Frequência de Falhas**: Acompanhamento por janela deslizante para acusar sequências excessivas de reinicializações antes de paradas completas.
- **Supervisão de Limites do Sistema Hospedeiro**: Alertas configuráveis para consumo de CPU e memória com prevenção de notificações duplicadas e períodos de resfriamento.
- **Transmissão Contínua de Logs em Tempo Real**: Conexão WebSocket padrão RFC 6455 (`/api/docker/logs`) com separação de canais stdout/stderr do Docker e recuperação via requisições REST JSON.
- **Inspeção de Socket Docker e Controle Operacional**: Leitura de contêineres em execução com caixas de diálogo para confirmação de paradas e reinicializações seguras.
- **Telemetria do Host**: Acompanhamento instantâneo de núcleos de CPU, goroutines ativas, memória RAM alocada, ciclos de coleta de lixo (GC) e tempo de atividade contínuo.
- **Compilação Multiplataforma**: Testado e homologado para Linux (amd64, arm64), macOS (amd64, arm64 Apple Silicon) e Windows (amd64).

---

## 🚀 Início Rápido (Quick Start)

### 1. Baixar e Executar (Binário Autônomo)

```bash
# Clonar o repositório
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# Executar diretamente com Go (porta HTTP padrão: 9080)
go run .
```

O console web integrado estará acessível imediatamente em:
👉 **`http://localhost:9080`**

### 2. Executar com TLS e Autenticação (Modo Seguro para Produção)

```bash
# Habilitar TLS autoassinado e configurar tokens de acesso
go run . --tls --admin-token="meu-token-super-secreto" --viewer-token="meu-token-somente-leitura"
```

Acesso ao painel seguro:
👉 **`https://localhost:9080`**

### 3. Compilar em Binário Único

```bash
# Compila um arquivo executável otimizado sem símbolos de depuração
go build -ldflags="-s -w" -o dock-radar .

# Consultar instruções de uso
./dock-radar --help
```

### 4. Opções de Configuração e Variáveis de Ambiente

| Parâmetro CLI | Variável de Ambiente | Valor Padrão | Descrição |
| :--- | :--- | :--- | :--- |
| `--port` | `PORT` | `9080` | Porta TCP para escuta do painel e da API |
| `--tls` | `DOCK_RADAR_TLS` | `false` | Ativa transporte seguro via HTTPS |
| `--tls-cert` | `DOCK_RADAR_TLS_CERT` | `""` | Caminho do arquivo PEM do certificado TLS |
| `--tls-key` | `DOCK_RADAR_TLS_KEY` | `""` | Caminho do arquivo PEM da chave privada TLS |
| `--admin-token` | `DOCK_RADAR_ADMIN_TOKEN` | `""` | Token Bearer com privilégios totais de administração |
| `--viewer-token` | `DOCK_RADAR_VIEWER_TOKEN`| `""` | Token Bearer para consulta de métricas somente leitura |
| `--allow-remote` | `DOCK_RADAR_ALLOW_REMOTE`| `false` | Permite conexões externas sem validação de loopback |
| `--nodes` | `DOCK_RADAR_NODES` | `""` | Lista de nós remotos do dock-radar para agregar (separados por vírgula) |
| `--node-name` | `DOCK_RADAR_NODE_NAME` | `hostname` | Nome de exibição atribuído a este nó |
| `--mesh-discovery` | `DOCK_RADAR_MESH_DISCOVERY` | `false` | Ativa autodescoberta de nós na rede local via difusão UDP |
| `--mesh-port` | `DOCK_RADAR_MESH_PORT` | `9085` | Porta UDP para envio de balizas na rede local |
| `--gossip-interval` | `DOCK_RADAR_GOSSIP_INTERVAL` | `5s` | Intervalo entre checagens no cluster SWIM Gossip |
| `--version` | — | — | Exibe a versão instalada do dock-radar e encerra |

---

## 🏛️ Arquitetura e Segurança (Architecture & Security)

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

### Garantias de Segurança (Security Guarantees)
- **Criptografia em Trânsito (TLS)**: Emissão sob demanda de certificados ECDSA P-256 com suporte SAN para localhost ou configuração de certificados de terceiros.
- **Verificação em Tempo Constante**: A conferência de tokens é processada por `crypto/subtle.ConstantTimeCompare`, neutralizando tentativas de ataque por tempo de resposta.
- **Controle RBAC Rigoroso**: Consultas de métricas e leituras são abertas aos perfis `viewer` e `admin`, enquanto ordens de reinício ou parada exigem autorização de `admin`.
- **Restrição de Loopback por Padrão**: Se nenhum token for informado, endpoints de mutação ficam acessíveis apenas via loopback local (`127.0.0.1`, `::1`, `localhost`).
- **Bloqueio de CSRF e Reassociação DNS**: Conferência obrigatória de metadados de navegação (`Sec-Fetch-Site`) e cabeçalhos `Origin`/`Referer`.
- **Prevenção de SSRF e Filtragem de Metadados**: Destinos de webhook exigem protocolos HTTP/HTTPS válidos, rejeitam quebras de linha (CRLF) e bloqueiam endereços de provedores em nuvem (`169.254.169.254`, `metadata.google.internal`).
- **Saneamento de Parâmetros**: Nomes e identificadores de contêineres são validados contra a expressão regular `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`.
- **Proteção contra Sobrecarga**: O limitador de taxa por balde de tokens suporta rajadas de até 5 comandos com reabastecimento contínuo de 1 token/segundo.

---

## 📡 Referência das APIs REST e WebSocket

| Endpoint | Método / Protocolo | Papel Necessário | Descrição |
| :--- | :---: | :---: | :--- |
| `/metrics` | `GET` | `viewer` | Métricas operacionais no formato Prometheus para coleta via Grafana |
| `/api/system` | `GET` | `viewer` | Nome da máquina, SO/arquitetura, núcleos de CPU, goroutines, RAM (MB), GC e uptime |
| `/api/docker` | `GET` | `viewer` | Status do daemon Docker, quantitativo de contêineres e parâmetros detalhados |
| `/api/docker/batch` | `POST` | `admin` | Ações agrupadas: `restart_all`, `stop_all`, `prune` (`{"action":"restart_all","timeout":10}`) |
| `/api/docker/logs` | `WS` / `GET` | `viewer` | Transmissão contínua de logs por WebSocket ou captura instantânea JSON (`?id=<id>&tail=100`) |
| `/api/docker/restart` | `POST` | `admin` | Reinício seguro de contêiner por ID ou nome (`{"id":"<id>","timeout":10}`) |
| `/api/docker/stop` | `POST` | `admin` | Interrupção controlada de contêiner ativo (`{"id":"<id>","timeout":10}`) |
| `/api/healing/config` | `GET` / `POST` | `viewer` / `admin` | Consulta ou atualiza diretrizes de autorrecuperação e exceções |
| `/api/healing/status` | `GET` | `viewer` | Indicadores de recuperação, contêineres em quarentena e intervalos de espera |
| `/api/healing/history`| `GET` | `viewer` | Histórico dos eventos recentes de auto-recuperação (`?limit=50`) |
| `/api/healing/reset`  | `POST` | `admin` | Desativa o bloqueio do disjuntor e zera os contadores de tolerância |
| `/api/nodes` | `GET` / `POST` / `DELETE` | `viewer` / `admin` | Inventário de nós, cadastro dinâmico e remoção de participantes |
| `/api/nodes/heartbeat` | `POST` | `viewer` | Canal de recebimento de telemetria e sincronização de agentes externos |
| `/api/cluster/summary` | `GET` | `viewer` | Visão consolidada da infraestrutura (nós ativos, CPU, memória e contêineres) |
| `/api/cluster/containers` | `GET` | `viewer` | Catálogo unificado de contêineres distribuídos na malha (`?node_id=&state=`) |
| `/api/mesh/discovery` | `GET` / `POST` | `viewer` / `admin` | Diagnóstico da autodescoberta UDP e disparo manual de sinalização |
| `/api/mesh/gossip` | `GET` / `POST` | `viewer` / `none` | Consulta do status na rede SWIM Gossip e recepção de pacotes P2P |
| `/api/audit/export` | `GET` | `viewer` | Exportação de eventos de auditoria em NDJSON ou JSON (`?format=ndjson&limit=2000`) |
| `/api/alerts/config` | `GET` / `POST` | `viewer` / `admin` | Ajuste de políticas de alarme, rotas de webhook e tetos de disparo |
| `/api/alerts/events` | `GET` | `viewer` | Histórico de ocorrências e incidentes recentes registrados (`?limit=50`) |
| `/api/alerts/test` | `POST` | `admin` | Envio de notificação de teste para Discord ou Slack |
| `/api/auth/status` | `GET` | `none` | Retorna status de TLS, permissões de acesso e o papel ativo |
| `/api/auth/verify` | `POST` | `none` | Valida um token Bearer e retorna as credenciais atribuídas |
| `/` | `GET` | `none` | Provê a interface web de página única integrada |

---

## 🗺️ Roteiro de Atualizações (Roadmap)

Consulte o documento [ROADMAP.md](../../ROADMAP.md) para conhecer marcos futuros, melhorias em desenvolvimento e o histórico de lançamentos.

---

## 🔒 Segurança (Security)

Para detalhes sobre notificação e reporte responsável de falhas, veja [SECURITY.md](../../SECURITY.md).

---

## 📄 Licença (License)

Distribuído sob a licença [Apache License 2.0](../../LICENSE).
