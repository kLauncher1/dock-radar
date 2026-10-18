package scanner

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Severity represents the standardized CVSS vulnerability severity grade.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

// ParseSeverity sanitizes and parses a severity string.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// Weight returns the numeric CVSS impact weight for ranking.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// PackageType defines the package manager or ecosystem origin of an artifact.
type PackageType string

const (
	PackageTypeAPK     PackageType = "apk"
	PackageTypeDPKG    PackageType = "deb"
	PackageTypeRPM     PackageType = "rpm"
	PackageTypeGolang  PackageType = "golang"
	PackageTypeNPM     PackageType = "npm"
	PackageTypePyPI    PackageType = "pypi"
	PackageTypeGeneric PackageType = "generic"
)

// Vulnerability defines an identified CVE entry impacting a software package.
type Vulnerability struct {
	ID               string    `json:"id"`
	Severity         Severity  `json:"severity"`
	CVSS             float64   `json:"cvss"`
	Package          string    `json:"package"`
	InstalledVersion string    `json:"installed_version"`
	FixedVersion     string    `json:"fixed_version"`
	Title            string    `json:"title"`
	Description      string    `json:"description,omitempty"`
	AdvisoryURL      string    `json:"advisory_url,omitempty"`
	PublishedAt      time.Time `json:"published_at,omitempty"`
}

// PackageInfo details an installed software package or library inside a container image.
type PackageInfo struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	Type       PackageType `json:"type"`
	PURL       string      `json:"purl"`
	License    string      `json:"license,omitempty"`
	Checksum   string      `json:"checksum,omitempty"`
	LayerIndex int         `json:"layer_index"`
}

// ImageLayer represents an immutable filesystem layer in the container image.
type ImageLayer struct {
	Index   int    `json:"index"`
	Digest  string `json:"digest"`
	Size    int64  `json:"size"`
	Command string `json:"command,omitempty"`
}

// GatingStatus represents the outcome of deployment security gating evaluation.
type GatingStatus string

const (
	GatingStatusPass    GatingStatus = "PASS"
	GatingStatusBlocked GatingStatus = "BLOCKED"
	GatingStatusWarning GatingStatus = "WARNING"
)

// GatingPolicy sets the security thresholds for deployment compliance.
type GatingPolicy struct {
	FailOnSeverity  Severity `json:"fail_on_severity"`
	MaxCritical     int      `json:"max_critical"`
	MaxHigh         int      `json:"max_high"`
	BlockUnscanned  bool     `json:"block_unscanned"`
	WhitelistCVEs   []string `json:"whitelist_cves,omitempty"`
	AllowedLicenses []string `json:"allowed_licenses,omitempty"`
}

// DefaultGatingPolicy constructs default production security gating parameters.
func DefaultGatingPolicy() GatingPolicy {
	return GatingPolicy{
		FailOnSeverity:  SeverityCritical,
		MaxCritical:     0,
		MaxHigh:         3,
		BlockUnscanned:  false,
		WhitelistCVEs:   []string{},
		AllowedLicenses: []string{},
	}
}

// GatingResult records the pass/blocked status and reasons of a policy evaluation.
type GatingResult struct {
	Status      GatingStatus `json:"status"`
	Passed      bool         `json:"passed"`
	Reason      string       `json:"reason"`
	Violations  []string     `json:"violations,omitempty"`
	EvaluatedAt time.Time    `json:"evaluated_at"`
}

// ScanReport encapsulates comprehensive vulnerability and SBOM audit results.
type ScanReport struct {
	ID              string          `json:"id"`
	ImageID         string          `json:"image_id"`
	ImageName       string          `json:"image_name"`
	ContainerID     string          `json:"container_id,omitempty"`
	Digest          string          `json:"digest"`
	OSName          string          `json:"os_name"`
	OSVersion       string          `json:"os_version"`
	Layers          []ImageLayer    `json:"layers"`
	Packages        []PackageInfo   `json:"packages"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	CriticalCount   int             `json:"critical_count"`
	HighCount       int             `json:"high_count"`
	MediumCount     int             `json:"medium_count"`
	LowCount        int             `json:"low_count"`
	RiskScore       float64         `json:"risk_score"`
	SecurityGrade   string          `json:"security_grade"`
	GatingResult    GatingResult    `json:"gating_result"`
	ScannedAt       time.Time       `json:"scanned_at"`
	DurationMs      int64           `json:"duration_ms"`
}

// ScannerStatus summarizes global vulnerability scanning operations and metrics.
type ScannerStatus struct {
	Enabled             bool      `json:"enabled"`
	AutoScan            bool      `json:"auto_scan"`
	TotalScannedImages  int       `json:"total_scanned_images"`
	TotalVulnerabilities int      `json:"total_vulnerabilities"`
	CriticalCount       int       `json:"critical_count"`
	HighCount           int       `json:"high_count"`
	MediumCount         int       `json:"medium_count"`
	LowCount            int       `json:"low_count"`
	AverageRiskScore    float64   `json:"average_risk_score"`
	GatingPassedCount   int       `json:"gating_passed_count"`
	GatingBlockedCount  int       `json:"gating_blocked_count"`
	LastScanAt          time.Time `json:"last_scan_at"`
}

// ScannerConfig controls scanner behaviors and intervals.
type ScannerConfig struct {
	Enabled         bool         `json:"enabled"`
	AutoScan        bool         `json:"auto_scan"`
	ScanIntervalSec int          `json:"scan_interval_sec"`
	CacheTTLMinutes int          `json:"cache_ttl_minutes"`
	GatingPolicy    GatingPolicy `json:"gating_policy"`
}

// DefaultScannerConfig returns default runtime configuration for the scanner.
func DefaultScannerConfig() ScannerConfig {
	return ScannerConfig{
		Enabled:         true,
		AutoScan:        true,
		ScanIntervalSec: 60,
		CacheTTLMinutes: 30,
		GatingPolicy:    DefaultGatingPolicy(),
	}
}

// Validate checks configuration sanity.
func (cfg ScannerConfig) Validate() error {
	if cfg.ScanIntervalSec < 5 && cfg.Enabled {
		return errors.New("scan_interval_sec must be at least 5 seconds")
	}
	if cfg.CacheTTLMinutes < 1 {
		return errors.New("cache_ttl_minutes must be at least 1 minute")
	}
	if cfg.GatingPolicy.MaxCritical < 0 {
		return errors.New("max_critical cannot be negative")
	}
	if cfg.GatingPolicy.MaxHigh < 0 {
		return errors.New("max_high cannot be negative")
	}
	return nil
}

// ScanFilter allows querying reports matching specific criteria.
type ScanFilter struct {
	ContainerID  string       `json:"container_id,omitempty"`
	ImageName    string       `json:"image_name,omitempty"`
	MinSeverity  Severity     `json:"min_severity,omitempty"`
	GatingStatus GatingStatus `json:"gating_status,omitempty"`
	Limit        int          `json:"limit,omitempty"`
}

// CalculateRiskScore computes a normalized 0-100 risk score and security letter grade.
// Lower risk score is better (0 = pristine, 100 = critical threat).
func CalculateRiskScore(critical, high, medium, low int) (float64, string) {
	// Weighted vulnerability impact formula
	rawScore := float64(critical*25 + high*10 + medium*3 + low*1)
	if rawScore > 100.0 {
		rawScore = 100.0
	}
	riskScore := math.Round(rawScore*10) / 10

	var grade string
	switch {
	case critical > 0 || riskScore >= 50.0:
		grade = "F"
	case high > 3 || riskScore >= 35.0:
		grade = "D"
	case high > 0 || riskScore >= 20.0:
		grade = "C"
	case medium > 2 || riskScore >= 10.0:
		grade = "B"
	case riskScore > 0:
		grade = "A"
	default:
		grade = "A+"
	}

	return riskScore, grade
}

// FormatPURL constructs a Package URL string following the purl specification.
func FormatPURL(pkgType PackageType, namespace, name, version string) string {
	cleanName := strings.TrimSpace(name)
	cleanVer := strings.TrimSpace(version)
	if namespace != "" {
		return fmt.Sprintf("pkg:%s/%s/%s@%s", pkgType, namespace, cleanName, cleanVer)
	}
	return fmt.Sprintf("pkg:%s/%s@%s", pkgType, cleanName, cleanVer)
}
