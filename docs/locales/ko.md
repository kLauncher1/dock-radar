<div align="center">

<!-- 10-Language Navigation Bar -->
<p align="center">
  <a href="../../README.md">🇺🇸 English</a> · <b>🇰🇷 한국어</b> · <a href="./zh-CN.md">🇨🇳 简体中文</a> · <a href="./ja.md">🇯🇵 日本語</a> · <a href="./es.md">🇪🇸 Español</a><br />
  <a href="./fr.md">🇫🇷 Français</a> · <a href="./ru.md">🇷🇺 Русский</a> · <a href="./pt-BR.md">🇧🇷 Português</a> · <a href="./ar.md">🇸🇦 العربية</a> · <a href="./hi.md">🇮🇳 हिन्दी</a>
</p>

# 📡 Dock-Radar

**초경량 단일 바이너리 컨테이너 & 호스트 시스템 메트릭 모니터링 엔진 (다크모드 웹 대시보드 내장)**

<sub>kLauncher1 제작 · 홈랩 및 엣지 노드를 위한 초저자원 설계</sub>

</div>

---

## ⚡ 주요 특징

- **단일 바이너리 배포**: Go `//go:embed` 기능을 통해 웹 대시보드를 바이너리에 직접 내장. Node.js 런타임이나 별도 웹서버 불필요.
- **초저용량 메모리 점유**: 상시 메모리 사용량 **15 MB 미만**으로 동작하여 저사양 VPS 및 라즈베리파이에 최적.
- **도커 소켓 직통 통신**: `/var/run/docker.sock` (Linux/macOS) 및 네임드 파이프(Windows)와 직접 통신하며 오프라인 장애 시 탄력적 폴백 지원.
- **호스트 시스템 텔레메트리**: 실시간 CPU 코어, 고루틴, 할당 메모리, GC 사이클 및 가동 시간 계측.
- **다크모드 글래스모피즘 UI**: 컨테이너 실시간 상태, 헬스 체크, 이벤트 로그를 직관적으로 제공하는 고대비 웹 콘솔.

---

## 🚀 빠른 시작

### 1. 다운로드 및 실행 (독립 바이너리)

```bash
# 저장소 복제
git clone https://github.com/kLauncher1/dock-radar.git
cd dock-radar

# Go 직접 실행
go run .
```

내장 웹 콘솔은 브라우저에서 즉시 접속 가능합니다:
👉 **`http://localhost:9080`**

### 2. 단일 바이너리 빌드

```bash
# 불필요한 심볼을 제거한 초소형 독립 실행 파일 빌드
go build -ldflags="-s -w" -o dock-radar .

# 바이너리 실행
./dock-radar
```

### 3. 포트 커스텀 설정

```bash
PORT=8080 ./dock-radar
```

---

## 🧪 테스트 실행

```bash
go test -v ./...
```

---

<sub>Copyright © 2026 kLauncher1. Apache-2.0 License.</sub>
