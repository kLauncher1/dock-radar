# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-13

### Added
- Single-binary zero-dependency container monitor architecture using Go `//go:embed`.
- Low-overhead Docker socket client (`/var/run/docker.sock` and Windows Named Pipe) with resilient offline fallback.
- Host system telemetry collector for real-time CPU, RAM, goroutines, and GC stats.
- Dark-mode glassmorphism web console dashboard with real-time JSON polling endpoints (`/api/system`, `/api/docker`).
- Ultra-low memory footprint operating persistently under 15 MB of RAM.
- Comprehensive unit test suite with 100% test pass rate.
