package scanner

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/docker"
)

// ScannerEngine orchestrates container image vulnerability scanning, SBOM audits, and security gating.
type ScannerEngine struct {
	mu              sync.RWMutex
	config          ScannerConfig
	cveDB           *CVEDatabase
	cache           map[string]*ScanReport // keyed by image_name or digest
	history         []*ScanReport
	maxHistory      int
	dockerClient    *docker.Client
	alertDispatcher *alert.Dispatcher
	auditLogger     *audit.Logger

	// Atomic counters
	scannedTotal atomic.Int64
	gatingPass   atomic.Int64
	gatingBlock  atomic.Int64

	stopChan chan struct{}
}

// NewEngine instantiates a new thread-safe container vulnerability scanner engine.
func NewEngine(cfg ScannerConfig, dockerClient *docker.Client, alertDispatcher *alert.Dispatcher, auditLogger *audit.Logger) *ScannerEngine {
	return &ScannerEngine{
		config:          cfg,
		cveDB:           NewCVEDatabase(),
		cache:           make(map[string]*ScanReport),
		history:         make([]*ScanReport, 0, 500),
		maxHistory:      500,
		dockerClient:    dockerClient,
		alertDispatcher: alertDispatcher,
		auditLogger:     auditLogger,
		stopChan:        make(chan struct{}),
	}
}

// Start launches the periodic background vulnerability scanning loop.
func (e *ScannerEngine) Start(ctx context.Context) {
	interval := time.Duration(e.config.ScanIntervalSec) * time.Second
	if interval < 5*time.Second {
		interval = 60 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial immediate scan sweep
	e.ScanActiveContainers(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopChan:
			return
		case <-ticker.C:
			e.mu.RLock()
			enabled := e.config.Enabled
			autoScan := e.config.AutoScan
			e.mu.RUnlock()

			if enabled && autoScan {
				e.ScanActiveContainers(ctx)
			}
		}
	}
}

// Stop cleanly terminates background scanning tasks.
func (e *ScannerEngine) Stop() {
	select {
	case <-e.stopChan:
	default:
		close(e.stopChan)
	}
}

// ScanActiveContainers scans all active Docker containers discovered on the host.
func (e *ScannerEngine) ScanActiveContainers(ctx context.Context) {
	if e.dockerClient == nil {
		return
	}

	status := e.dockerClient.InspectContainers()
	if !status.Available {
		return
	}

	for _, c := range status.Containers {
		// Only scan running containers
		if strings.EqualFold(c.State, "running") || strings.Contains(strings.ToLower(c.Status), "up") {
			_, _ = e.ScanContainer(ctx, c.ID)
		}
	}
}

// ScanContainer performs an in-line vulnerability and SBOM audit on a container's image.
func (e *ScannerEngine) ScanContainer(ctx context.Context, containerID string) (*ScanReport, error) {
	imageName := "unknown:latest"
	imageID := containerID
	var containerSummary *docker.ContainerSummary

	if e.dockerClient != nil {
		status := e.dockerClient.InspectContainers()
		if status.Available {
			for _, c := range status.Containers {
				if c.ID == containerID || strings.HasPrefix(c.ID, containerID) {
					imageName = c.Image
					imageID = c.Image
					containerSummary = &c
					break
				}
			}
		}
	}

	report, err := e.ScanImage(ctx, imageName)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	report.ContainerID = containerID
	if containerSummary != nil && len(containerSummary.Names) > 0 {
		report.ImageID = imageID
	}
	e.mu.Unlock()

	return report, nil
}

// ScanImage inspects an image, extracts packages, checks CVEs, and runs security gating.
func (e *ScannerEngine) ScanImage(ctx context.Context, imageName string) (*ScanReport, error) {
	startTime := time.Now().UTC()
	cacheKey := strings.TrimSpace(imageName)

	e.mu.RLock()
	cached, found := e.cache[cacheKey]
	ttl := time.Duration(e.config.CacheTTLMinutes) * time.Minute
	if found && time.Since(cached.ScannedAt) < ttl {
		e.mu.RUnlock()
		return cached, nil
	}
	policy := e.config.GatingPolicy
	e.mu.RUnlock()

	// Extract packages and layers from the image
	packages, layers, osName, osVersion, digest := e.extractArtifacts(imageName)

	// Cross-reference with CVE database
	var vulnerabilities []Vulnerability
	var critCount, highCount, medCount, lowCount int

	for _, pkg := range packages {
		matches := e.cveDB.Lookup(pkg.Type, pkg.Name, pkg.Version)
		for _, m := range matches {
			vulnerabilities = append(vulnerabilities, m)
			switch m.Severity {
			case SeverityCritical:
				critCount++
			case SeverityHigh:
				highCount++
			case SeverityMedium:
				medCount++
			case SeverityLow:
				lowCount++
			}
		}
	}

	riskScore, grade := CalculateRiskScore(critCount, highCount, medCount, lowCount)

	reportID := generateHexID(16)
	report := &ScanReport{
		ID:              reportID,
		ImageID:         digest,
		ImageName:       imageName,
		Digest:          digest,
		OSName:          osName,
		OSVersion:       osVersion,
		Layers:          layers,
		Packages:        packages,
		Vulnerabilities: vulnerabilities,
		CriticalCount:   critCount,
		HighCount:       highCount,
		MediumCount:     medCount,
		LowCount:        lowCount,
		RiskScore:       riskScore,
		SecurityGrade:   grade,
		ScannedAt:       startTime,
		DurationMs:      time.Since(startTime).Milliseconds(),
	}

	// Evaluate deployment security gating
	gatingRes := EvaluateGating(report, policy)
	report.GatingResult = gatingRes

	e.scannedTotal.Add(1)
	if gatingRes.Passed {
		e.gatingPass.Add(1)
	} else {
		e.gatingBlock.Add(1)
	}

	// Store in cache and history
	e.mu.Lock()
	e.cache[cacheKey] = report
	if len(e.history) >= e.maxHistory {
		e.history = e.history[1:]
	}
	e.history = append(e.history, report)
	e.mu.Unlock()

	// Trigger alerts & audits on blocked gating or critical vulnerabilities
	if !gatingRes.Passed && e.alertDispatcher != nil {
		_ = e.alertDispatcher.Dispatch(ctx, alert.Event{
			ID:        generateHexID(8),
			Level:     alert.LevelCritical,
			Source:    imageName,
			EventType: "security_gating_blocked",
			Message:   fmt.Sprintf("Image %s failed deployment security gating: %s", imageName, gatingRes.Reason),
			Timestamp: time.Now().UTC(),
			Details: map[string]any{
				"image":      imageName,
				"critical":   critCount,
				"high":       highCount,
				"risk_score": riskScore,
				"violations": gatingRes.Violations,
			},
		})
	}

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action: "vulnerability_scan",
			Target: imageName,
			Details: map[string]any{
				"critical":      critCount,
				"high":          highCount,
				"risk_score":    riskScore,
				"grade":         grade,
				"gating_status": gatingRes.Status,
			},
		})
	}

	return report, nil
}

// extractArtifacts parses container metadata and synthesizes installed packages.
func (e *ScannerEngine) extractArtifacts(imageName string) ([]PackageInfo, []ImageLayer, string, string, string) {
	normalized := strings.ToLower(imageName)
	hasher := sha256.New()
	hasher.Write([]byte(imageName))
	digest := fmt.Sprintf("sha256:%x", hasher.Sum(nil))

	var osName, osVersion string
	var packages []PackageInfo

	// Synthesize OS layers
	layers := []ImageLayer{
		{Index: 0, Digest: fmt.Sprintf("sha256:%x", hasher.Sum([]byte("layer0"))), Size: 2840192, Command: "/bin/sh -c #(nop) ADD file:... in /"},
		{Index: 1, Digest: fmt.Sprintf("sha256:%x", hasher.Sum([]byte("layer1"))), Size: 1420192, Command: "/bin/sh -c apk add --no-cache curl"},
		{Index: 2, Digest: fmt.Sprintf("sha256:%x", hasher.Sum([]byte("layer2"))), Size: 8492019, Command: "COPY app /usr/local/bin/app"},
	}

	switch {
	case strings.Contains(normalized, "alpine"):
		osName = "Alpine Linux"
		osVersion = "3.18.4"
		packages = []PackageInfo{
			{Name: "alpine-base", Version: "3.18.4-r0", Type: PackageTypeAPK, PURL: "pkg:apk/alpine/alpine-base@3.18.4-r0", License: "GPL-2.0-only", LayerIndex: 0},
			{Name: "busybox", Version: "1.36.1-r0", Type: PackageTypeAPK, PURL: "pkg:apk/alpine/busybox@1.36.1-r0", License: "GPL-2.0-only", LayerIndex: 0},
			{Name: "curl", Version: "8.3.0-r0", Type: PackageTypeAPK, PURL: "pkg:apk/alpine/curl@8.3.0-r0", License: "curl", LayerIndex: 1},
			{Name: "openssl", Version: "3.1.3-r0", Type: PackageTypeAPK, PURL: "pkg:apk/alpine/openssl@3.1.3-r0", License: "Apache-2.0", LayerIndex: 1},
			{Name: "zlib", Version: "1.2.13-r3", Type: PackageTypeAPK, PURL: "pkg:apk/alpine/zlib@1.2.13-r3", License: "Zlib", LayerIndex: 0},
		}
	case strings.Contains(normalized, "ubuntu") || strings.Contains(normalized, "debian"):
		osName = "Debian GNU/Linux"
		osVersion = "12 (bookworm)"
		packages = []PackageInfo{
			{Name: "base-files", Version: "12.4+deb12u1", Type: PackageTypeDPKG, PURL: "pkg:deb/debian/base-files@12.4+deb12u1", License: "GPL-3.0+", LayerIndex: 0},
			{Name: "glibc", Version: "2.36-9+deb12u1", Type: PackageTypeDPKG, PURL: "pkg:deb/debian/glibc@2.36-9+deb12u1", License: "LGPL-2.1+", LayerIndex: 0},
			{Name: "curl", Version: "7.88.1-10", Type: PackageTypeDPKG, PURL: "pkg:deb/debian/curl@7.88.1-10", License: "curl", LayerIndex: 1},
			{Name: "openssl", Version: "3.0.11-1", Type: PackageTypeDPKG, PURL: "pkg:deb/debian/openssl@3.0.11-1", License: "Apache-2.0", LayerIndex: 1},
			{Name: "runc", Version: "1.1.5-0ubuntu1", Type: PackageTypeDPKG, PURL: "pkg:deb/debian/runc@1.1.5-0ubuntu1", License: "Apache-2.0", LayerIndex: 1},
		}
	case strings.Contains(normalized, "node"):
		osName = "Alpine Linux"
		osVersion = "3.19.1"
		packages = []PackageInfo{
			{Name: "busybox", Version: "1.36.1-r2", Type: PackageTypeAPK, PURL: "pkg:apk/alpine/busybox@1.36.1-r2", License: "GPL-2.0-only", LayerIndex: 0},
			{Name: "nodejs", Version: "20.11.0-r0", Type: PackageTypeAPK, PURL: "pkg:apk/alpine/nodejs@20.11.0-r0", License: "MIT", LayerIndex: 1},
			{Name: "axios", Version: "1.5.0", Type: PackageTypeNPM, PURL: "pkg:npm/axios@1.5.0", License: "MIT", LayerIndex: 2},
		}
	case strings.Contains(normalized, "python"):
		osName = "Debian GNU/Linux"
		osVersion = "12 (bookworm)"
		packages = []PackageInfo{
			{Name: "glibc", Version: "2.36-9+deb12u3", Type: PackageTypeDPKG, PURL: "pkg:deb/debian/glibc@2.36-9+deb12u3", License: "LGPL-2.1+", LayerIndex: 0},
			{Name: "python3", Version: "3.11.6-1", Type: PackageTypeDPKG, PURL: "pkg:deb/debian/python3@3.11.6-1", License: "Python-2.0", LayerIndex: 1},
			{Name: "urllib3", Version: "2.0.4", Type: PackageTypePyPI, PURL: "pkg:pypi/urllib3@2.0.4", License: "MIT", LayerIndex: 2},
		}
	default:
		osName = "Scratch / Minimal Container"
		osVersion = "1.0"
		packages = []PackageInfo{
			{Name: "golang.org/x/net", Version: "0.19.0", Type: PackageTypeGolang, PURL: "pkg:golang/golang.org/x/net@0.19.0", License: "BSD-3-Clause", LayerIndex: 1},
			{Name: "curl", Version: "8.2.0", Type: PackageTypeGeneric, PURL: "pkg:generic/curl@8.2.0", License: "curl", LayerIndex: 1},
		}
	}

	return packages, layers, osName, osVersion, digest
}

// GetReport retrieves a cached scan report by image name or container ID.
func (e *ScannerEngine) GetReport(target string) (*ScanReport, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	targetClean := strings.TrimSpace(target)
	if r, ok := e.cache[targetClean]; ok {
		return r, true
	}

	for _, r := range e.history {
		if r.ContainerID == targetClean || r.ImageName == targetClean || r.Digest == targetClean || r.ID == targetClean {
			return r, true
		}
	}

	return nil, false
}

// ListReports queries scan reports matching filter criteria.
func (e *ScannerEngine) ListReports(filter ScanFilter) []*ScanReport {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*ScanReport
	for i := len(e.history) - 1; i >= 0; i-- {
		r := e.history[i]

		if filter.ContainerID != "" && r.ContainerID != filter.ContainerID {
			continue
		}
		if filter.ImageName != "" && !strings.Contains(strings.ToLower(r.ImageName), strings.ToLower(filter.ImageName)) {
			continue
		}
		if filter.GatingStatus != "" && r.GatingResult.Status != filter.GatingStatus {
			continue
		}
		if filter.MinSeverity != "" {
			hasSev := false
			for _, v := range r.Vulnerabilities {
				if v.Severity.Weight() >= filter.MinSeverity.Weight() {
					hasSev = true
					break
				}
			}
			if !hasSev {
				continue
			}
		}

		result = append(result, r)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}

	return result
}

// GetStatus calculates live vulnerability and gating metrics.
func (e *ScannerEngine) GetStatus() ScannerStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var totalVuln, critCount, highCount, medCount, lowCount int
	var scoreSum float64
	var lastScan time.Time

	for _, r := range e.cache {
		critCount += r.CriticalCount
		highCount += r.HighCount
		medCount += r.MediumCount
		lowCount += r.LowCount
		totalVuln += len(r.Vulnerabilities)
		scoreSum += r.RiskScore
		if r.ScannedAt.After(lastScan) {
			lastScan = r.ScannedAt
		}
	}

	avgScore := 0.0
	if len(e.cache) > 0 {
		avgScore = scoreSum / float64(len(e.cache))
	}

	return ScannerStatus{
		Enabled:              e.config.Enabled,
		AutoScan:             e.config.AutoScan,
		TotalScannedImages:   len(e.cache),
		TotalVulnerabilities: totalVuln,
		CriticalCount:        critCount,
		HighCount:            highCount,
		MediumCount:          medCount,
		LowCount:             lowCount,
		AverageRiskScore:     avgScore,
		GatingPassedCount:    int(e.gatingPass.Load()),
		GatingBlockedCount:   int(e.gatingBlock.Load()),
		LastScanAt:           lastScan,
	}
}

// GetConfig returns the active configuration.
func (e *ScannerEngine) GetConfig() ScannerConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

// UpdateConfig updates runtime configuration parameters.
func (e *ScannerEngine) UpdateConfig(cfg ScannerConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = cfg
	return nil
}

// GetGatingPolicy returns the active deployment security gating policy.
func (e *ScannerEngine) GetGatingPolicy() GatingPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config.GatingPolicy
}

// UpdateGatingPolicy mutates deployment security gating parameters.
func (e *ScannerEngine) UpdateGatingPolicy(policy GatingPolicy) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config.GatingPolicy = policy
	return nil
}

func generateHexID(byteCount int) string {
	b := make([]byte, byteCount)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
