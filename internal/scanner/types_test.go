package scanner

import (
	"testing"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
	}{
		{"critical", SeverityCritical},
		{"CRITICAL", SeverityCritical},
		{"High", SeverityHigh},
		{"medium", SeverityMedium},
		{"low", SeverityLow},
		{"unknown", SeverityUnknown},
		{"", SeverityUnknown},
	}

	for _, tc := range tests {
		got := ParseSeverity(tc.input)
		if got != tc.expected {
			t.Errorf("ParseSeverity(%q) = %v; want %v", tc.input, got, tc.expected)
		}
	}
}

func TestSeverityWeight(t *testing.T) {
	if SeverityCritical.Weight() <= SeverityHigh.Weight() {
		t.Errorf("critical weight must exceed high weight")
	}
	if SeverityHigh.Weight() <= SeverityMedium.Weight() {
		t.Errorf("high weight must exceed medium weight")
	}
	if SeverityMedium.Weight() <= SeverityLow.Weight() {
		t.Errorf("medium weight must exceed low weight")
	}
}

func TestCalculateRiskScore(t *testing.T) {
	// Zero vulnerabilities
	score, grade := CalculateRiskScore(0, 0, 0, 0)
	if score != 0.0 || grade != "A+" {
		t.Errorf("expected 0.0 and A+, got %.1f and %s", score, grade)
	}

	// 1 Critical vulnerability -> Grade F
	score, grade = CalculateRiskScore(1, 0, 0, 0)
	if score < 25.0 || grade != "F" {
		t.Errorf("expected >=25.0 and F, got %.1f and %s", score, grade)
	}

	// Only 1 Medium vulnerability -> Grade A or B
	score, grade = CalculateRiskScore(0, 0, 1, 0)
	if score != 3.0 || grade != "A" {
		t.Errorf("expected 3.0 and A, got %.1f and %s", score, grade)
	}

	// Cap at 100.0
	score, grade = CalculateRiskScore(10, 10, 10, 10)
	if score != 100.0 || grade != "F" {
		t.Errorf("expected 100.0 and F, got %.1f and %s", score, grade)
	}
}

func TestFormatPURL(t *testing.T) {
	purl := FormatPURL(PackageTypeAPK, "alpine", "curl", "8.4.0-r0")
	expected := "pkg:apk/alpine/curl@8.4.0-r0"
	if purl != expected {
		t.Errorf("FormatPURL() = %q; want %q", purl, expected)
	}

	purlNoNamespace := FormatPURL(PackageTypeNPM, "", "axios", "1.6.0")
	expectedNoNamespace := "pkg:npm/axios@1.6.0"
	if purlNoNamespace != expectedNoNamespace {
		t.Errorf("FormatPURL() = %q; want %q", purlNoNamespace, expectedNoNamespace)
	}
}

func TestScannerConfig_Validate(t *testing.T) {
	valid := DefaultScannerConfig()
	if err := valid.Validate(); err != nil {
		t.Fatalf("DefaultScannerConfig should be valid: %v", err)
	}

	invalidInterval := valid
	invalidInterval.ScanIntervalSec = 2
	if err := invalidInterval.Validate(); err == nil {
		t.Errorf("expected error for scan_interval_sec < 5")
	}

	invalidTTL := valid
	invalidTTL.CacheTTLMinutes = 0
	if err := invalidTTL.Validate(); err == nil {
		t.Errorf("expected error for cache_ttl_minutes < 1")
	}

	invalidCrit := valid
	invalidCrit.GatingPolicy.MaxCritical = -1
	if err := invalidCrit.Validate(); err == nil {
		t.Errorf("expected error for max_critical < 0")
	}
}
