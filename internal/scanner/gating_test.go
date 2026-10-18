package scanner

import (
	"testing"
	"time"
)

func TestEvaluateGating_CleanPass(t *testing.T) {
	report := &ScanReport{
		ID:        "clean-report",
		ImageName: "clean:latest",
		ScannedAt: time.Now().UTC(),
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2023-1111", Severity: SeverityLow, Package: "pkg-a"},
		},
	}

	policy := DefaultGatingPolicy()
	res := EvaluateGating(report, policy)

	if !res.Passed || res.Status != GatingStatusPass {
		t.Errorf("expected pass, got %v (%s)", res.Status, res.Reason)
	}
	if len(res.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(res.Violations))
	}
}

func TestEvaluateGating_CriticalBlocked(t *testing.T) {
	report := &ScanReport{
		ID:        "vuln-report",
		ImageName: "vulnerable:latest",
		ScannedAt: time.Now().UTC(),
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2024-21626", Severity: SeverityCritical, Package: "runc"},
		},
	}

	policy := DefaultGatingPolicy()
	policy.MaxCritical = 0
	policy.FailOnSeverity = SeverityCritical

	res := EvaluateGating(report, policy)
	if res.Passed || res.Status != GatingStatusBlocked {
		t.Errorf("expected blocked gating, got %v (%s)", res.Status, res.Reason)
	}
	if len(res.Violations) == 0 {
		t.Errorf("expected violations for critical vulnerability")
	}
}

func TestEvaluateGating_WhitelistedCVE(t *testing.T) {
	report := &ScanReport{
		ID:        "whitelisted-report",
		ImageName: "app:latest",
		ScannedAt: time.Now().UTC(),
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2024-21626", Severity: SeverityCritical, Package: "runc"},
		},
	}

	policy := DefaultGatingPolicy()
	policy.WhitelistCVEs = []string{"CVE-2024-21626"}

	res := EvaluateGating(report, policy)
	if !res.Passed || res.Status != GatingStatusPass {
		t.Errorf("expected pass due to whitelist, got %v (%s)", res.Status, res.Reason)
	}
}

func TestEvaluateGating_LicenseCheck(t *testing.T) {
	report := &ScanReport{
		ID:        "license-report",
		ImageName: "licensed:latest",
		ScannedAt: time.Now().UTC(),
		Packages: []PackageInfo{
			{Name: "lib-a", Version: "1.0", License: "MIT"},
			{Name: "lib-b", Version: "2.0", License: "GPL-3.0-only"},
		},
	}

	policy := DefaultGatingPolicy()
	policy.AllowedLicenses = []string{"MIT", "Apache-2.0"}

	res := EvaluateGating(report, policy)
	if res.Passed || res.Status != GatingStatusBlocked {
		t.Errorf("expected blocked due to non-whitelisted GPL license, got %v", res.Status)
	}
}

func TestEvaluateGating_NilGuard(t *testing.T) {
	policy := DefaultGatingPolicy()
	res := EvaluateGating(nil, policy)
	if res.Passed || res.Status != GatingStatusBlocked {
		t.Errorf("nil report must yield blocked status")
	}
}
