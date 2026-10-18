package scanner

import (
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// VulnerabilityRecord defines an advisory record within the embedded vulnerability database.
type VulnerabilityRecord struct {
	CVE         string
	PackageType PackageType
	Package     string
	FixedAbove  string // Vulnerable if installed < FixedAbove
	Severity    Severity
	CVSS        float64
	Title       string
	Description string
	AdvisoryURL string
	PublishedAt time.Time
}

// CVEDatabase provides in-memory indexing and matching for known vulnerability advisories.
type CVEDatabase struct {
	mu      sync.RWMutex
	records []VulnerabilityRecord
}

// NewCVEDatabase initializes the vulnerability database with known container package CVEs.
func NewCVEDatabase() *CVEDatabase {
	db := &CVEDatabase{
		records: make([]VulnerabilityRecord, 0),
	}
	db.loadCuratedAdvisories()
	return db
}

// Lookup queries the database for matching vulnerabilities based on package type, name, and version.
func (db *CVEDatabase) Lookup(pkgType PackageType, pkgName, installedVersion string) []Vulnerability {
	db.mu.RLock()
	defer db.mu.RUnlock()

	normalizedName := strings.ToLower(strings.TrimSpace(pkgName))
	var matched []Vulnerability

	for _, rec := range db.records {
		if rec.PackageType != pkgType && rec.PackageType != PackageTypeGeneric {
			continue
		}
		if strings.ToLower(rec.Package) != normalizedName {
			continue
		}

		// Check if version is vulnerable (< fixed version)
		if IsVersionVulnerable(installedVersion, rec.FixedAbove) {
			matched = append(matched, Vulnerability{
				ID:               rec.CVE,
				Severity:         rec.Severity,
				CVSS:             rec.CVSS,
				Package:          rec.Package,
				InstalledVersion: installedVersion,
				FixedVersion:     rec.FixedAbove,
				Title:            rec.Title,
				Description:      rec.Description,
				AdvisoryURL:      rec.AdvisoryURL,
				PublishedAt:      rec.PublishedAt,
			})
		}
	}

	return matched
}

// AddAdvisory registers a custom vulnerability advisory dynamically.
func (db *CVEDatabase) AddAdvisory(rec VulnerabilityRecord) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.records = append(db.records, rec)
}

// Count returns the total number of advisories indexed.
func (db *CVEDatabase) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.records)
}

// loadCuratedAdvisories preloads high-profile CVEs commonly affecting container images.
func (db *CVEDatabase) loadCuratedAdvisories() {
	advisories := []VulnerabilityRecord{
		// Critical Container Runtime Breaches
		{
			CVE:         "CVE-2024-21626",
			PackageType: PackageTypeDPKG,
			Package:     "runc",
			FixedAbove:  "1.1.12",
			Severity:    SeverityCritical,
			CVSS:        8.6,
			Title:       "Container Escape via Leaked File Descriptor in runc",
			Description: "Internal file descriptor leakage in runc allows container processes to escape to the host filesystem.",
			AdvisoryURL: "https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
			PublishedAt: time.Date(2024, 1, 31, 0, 0, 0, 0, time.UTC),
		},
		// Network & HTTP Clients
		{
			CVE:         "CVE-2023-38545",
			PackageType: PackageTypeAPK,
			Package:     "curl",
			FixedAbove:  "8.4.0",
			Severity:    SeverityCritical,
			CVSS:        9.8,
			Title:       "SOCKS5 Heap Buffer Overflow in libcurl",
			Description: "Heap buffer overflow in SOCKS5 proxy handshake allows remote attackers to execute arbitrary code.",
			AdvisoryURL: "https://curl.se/docs/CVE-2023-38545.html",
			PublishedAt: time.Date(2023, 10, 11, 0, 0, 0, 0, time.UTC),
		},
		{
			CVE:         "CVE-2023-38545",
			PackageType: PackageTypeDPKG,
			Package:     "curl",
			FixedAbove:  "8.4.0",
			Severity:    SeverityCritical,
			CVSS:        9.8,
			Title:       "SOCKS5 Heap Buffer Overflow in libcurl",
			Description: "Heap buffer overflow in SOCKS5 proxy handshake allows remote attackers to execute arbitrary code.",
			AdvisoryURL: "https://curl.se/docs/CVE-2023-38545.html",
			PublishedAt: time.Date(2023, 10, 11, 0, 0, 0, 0, time.UTC),
		},
		// Core C Libraries
		{
			CVE:         "CVE-2023-6246",
			PackageType: PackageTypeDPKG,
			Package:     "glibc",
			FixedAbove:  "2.37",
			Severity:    SeverityHigh,
			CVSS:        7.8,
			Title:       "Heap-based Buffer Overflow in syslog function",
			Description: "Heap buffer overflow in GNU C Library syslog/vsyslog allows local privilege escalation.",
			AdvisoryURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-6246",
			PublishedAt: time.Date(2024, 1, 30, 0, 0, 0, 0, time.UTC),
		},
		// Cryptographic Libraries
		{
			CVE:         "CVE-2022-3602",
			PackageType: PackageTypeAPK,
			Package:     "openssl",
			FixedAbove:  "3.0.7",
			Severity:    SeverityHigh,
			CVSS:        7.5,
			Title:       "X.509 Email Address 4-byte Buffer Overrun in OpenSSL",
			Description: "Buffer overrun in X.509 certificate email address verification can lead to remote code execution or denial of service.",
			AdvisoryURL: "https://www.openssl.org/news/secadv/20221101.txt",
			PublishedAt: time.Date(2022, 11, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			CVE:         "CVE-2023-5363",
			PackageType: PackageTypeDPKG,
			Package:     "openssl",
			FixedAbove:  "3.0.12",
			Severity:    SeverityMedium,
			CVSS:        5.3,
			Title:       "Incorrect Cipher Key Truncation in OpenSSL",
			Description: "Key and IV length truncation in EVP ciphers leading to security downgrade.",
			AdvisoryURL: "https://www.openssl.org/news/secadv/20231024.txt",
			PublishedAt: time.Date(2023, 10, 24, 0, 0, 0, 0, time.UTC),
		},
		// Container OS Utilities
		{
			CVE:         "CVE-2022-30065",
			PackageType: PackageTypeAPK,
			Package:     "busybox",
			FixedAbove:  "1.36.0",
			Severity:    SeverityHigh,
			CVSS:        7.8,
			Title:       "Use-After-Free in BusyBox awk applet",
			Description: "Use-after-free vulnerability in Busybox awk engine when evaluating complex nested expressions.",
			AdvisoryURL: "https://nvd.nist.gov/vuln/detail/CVE-2022-30065",
			PublishedAt: time.Date(2022, 5, 18, 0, 0, 0, 0, time.UTC),
		},
		// Go Runtime & Dependencies
		{
			CVE:         "CVE-2023-45288",
			PackageType: PackageTypeGolang,
			Package:     "golang.org/x/net",
			FixedAbove:  "0.23.0",
			Severity:    SeverityHigh,
			CVSS:        7.5,
			Title:       "HTTP/2 Continuous CONTINUATION Frames Denial of Service",
			Description: "Unbounded header frame processing in Go net/http2 leads to excessive CPU and memory consumption.",
			AdvisoryURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-45288",
			PublishedAt: time.Date(2024, 4, 3, 0, 0, 0, 0, time.UTC),
		},
		// Node.js NPM Ecosystem
		{
			CVE:         "CVE-2023-45857",
			PackageType: PackageTypeNPM,
			Package:     "axios",
			FixedAbove:  "1.6.0",
			Severity:    SeverityHigh,
			CVSS:        7.5,
			Title:       "Cross-Site Request Forgery via Redirect Header Leakage",
			Description: "Axios sends authorization and cookie headers when redirected to third-party domains.",
			AdvisoryURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-45857",
			PublishedAt: time.Date(2023, 10, 24, 0, 0, 0, 0, time.UTC),
		},
		// Python PyPI Ecosystem
		{
			CVE:         "CVE-2023-45803",
			PackageType: PackageTypePyPI,
			Package:     "urllib3",
			FixedAbove:  "2.0.7",
			Severity:    SeverityHigh,
			CVSS:        7.5,
			Title:       "Cookie Leakage on Cross-Origin Redirects",
			Description: "Urllib3 fails to strip Cookie headers when redirected from HTTPS to HTTP across domains.",
			AdvisoryURL: "https://nvd.nist.gov/vuln/detail/CVE-2023-45803",
			PublishedAt: time.Date(2023, 10, 18, 0, 0, 0, 0, time.UTC),
		},
	}

	db.records = append(db.records, advisories...)
}

// IsVersionVulnerable checks whether installedVersion is strictly older than fixedVersion.
func IsVersionVulnerable(installedVersion, fixedVersion string) bool {
	if fixedVersion == "" {
		return true // No fix available; vulnerable by default
	}
	if installedVersion == "" {
		return false
	}
	return CompareVersions(installedVersion, fixedVersion) < 0
}

// CompareVersions performs a robust component-wise version comparison.
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func CompareVersions(v1, v2 string) int {
	clean1 := cleanVersionString(v1)
	clean2 := cleanVersionString(v2)

	parts1 := splitVersionParts(clean1)
	parts2 := splitVersionParts(clean2)

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 string
		if i < len(parts1) {
			p1 = parts1[i]
		}
		if i < len(parts2) {
			p2 = parts2[i]
		}

		num1, isNum1 := strconv.Atoi(p1)
		num2, isNum2 := strconv.Atoi(p2)

		if isNum1 == nil && isNum2 == nil {
			if num1 < num2 {
				return -1
			} else if num1 > num2 {
				return 1
			}
		} else {
			cmp := strings.Compare(p1, p2)
			if cmp != 0 {
				return cmp
			}
		}
	}

	return 0
}

func cleanVersionString(v string) string {
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	// Remove epoch e.g., "1:2.3.4"
	if idx := strings.Index(v, ":"); idx >= 0 {
		v = v[idx+1:]
	}
	return strings.TrimSpace(v)
}

func splitVersionParts(v string) []string {
	var parts []string
	var current strings.Builder

	for _, r := range v {
		if r == '.' || r == '-' || r == '+' || r == '~' || r == '_' {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		} else if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}
