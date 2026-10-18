package scanner

import (
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.2.0", "1.1.9", 1},
		{"v2.1.0", "2.1.0", 0},
		{"1:2.3.4", "2.3.4", 0},
		{"3.18.4-r0", "3.18.4-r1", -1},
		{"7.88.1-10", "7.88.1-10+deb12u5", -1},
		{"8.4.0", "8.3.0", 1},
	}

	for _, tc := range tests {
		got := CompareVersions(tc.v1, tc.v2)
		if got != tc.expected {
			t.Errorf("CompareVersions(%q, %q) = %d; want %d", tc.v1, tc.v2, got, tc.expected)
		}
	}
}

func TestIsVersionVulnerable(t *testing.T) {
	if !IsVersionVulnerable("8.3.0", "8.4.0") {
		t.Errorf("8.3.0 should be vulnerable compared to fixed 8.4.0")
	}
	if IsVersionVulnerable("8.4.0", "8.4.0") {
		t.Errorf("8.4.0 should not be vulnerable to fixed 8.4.0")
	}
	if IsVersionVulnerable("8.5.0", "8.4.0") {
		t.Errorf("8.5.0 should not be vulnerable to fixed 8.4.0")
	}
	if !IsVersionVulnerable("1.0.0", "") {
		t.Errorf("empty fixed version means no fix available, should be vulnerable")
	}
}

func TestCVEDatabase_Lookup(t *testing.T) {
	db := NewCVEDatabase()
	if db.Count() == 0 {
		t.Fatalf("expected non-zero advisories in curated DB")
	}

	// Lookup known vulnerable curl in APK
	vulns := db.Lookup(PackageTypeAPK, "curl", "8.3.0")
	if len(vulns) == 0 {
		t.Fatalf("expected at least 1 vulnerability for curl 8.3.0")
	}

	foundCrit := false
	for _, v := range vulns {
		if v.ID == "CVE-2023-38545" && v.Severity == SeverityCritical {
			foundCrit = true
			break
		}
	}
	if !foundCrit {
		t.Errorf("expected CVE-2023-38545 Critical vulnerability for curl 8.3.0")
	}

	// Lookup patched curl in APK
	vulnsPatched := db.Lookup(PackageTypeAPK, "curl", "8.5.0")
	if len(vulnsPatched) != 0 {
		t.Errorf("curl 8.5.0 should be clean, found %d vulns", len(vulnsPatched))
	}
}

func TestCVEDatabase_AddAdvisory(t *testing.T) {
	db := NewCVEDatabase()
	initialCount := db.Count()

	db.AddAdvisory(VulnerabilityRecord{
		CVE:         "CVE-2025-9999",
		PackageType: PackageTypeGolang,
		Package:     "custom-pkg",
		FixedAbove:  "2.0.0",
		Severity:    SeverityCritical,
		CVSS:        9.9,
		Title:       "Test Advisory",
		PublishedAt: time.Now().UTC(),
	})

	if db.Count() != initialCount+1 {
		t.Errorf("expected count %d; got %d", initialCount+1, db.Count())
	}

	vulns := db.Lookup(PackageTypeGolang, "custom-pkg", "1.5.0")
	if len(vulns) != 1 || vulns[0].ID != "CVE-2025-9999" {
		t.Errorf("failed to lookup newly registered advisory")
	}
}
