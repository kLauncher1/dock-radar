package scanner

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGenerateSPDX(t *testing.T) {
	report := &ScanReport{
		ID:          "test-report-1234",
		ImageID:     "sha256:abcdef1234567890",
		ImageName:   "redis:alpine",
		ScannedAt:   time.Now().UTC(),
		Digest:      "sha256:abcdef1234567890",
		Packages: []PackageInfo{
			{Name: "redis", Version: "7.2.3", Type: PackageTypeAPK, PURL: "pkg:apk/alpine/redis@7.2.3", License: "BSD-3-Clause"},
			{Name: "musl", Version: "1.2.4-r2", Type: PackageTypeAPK, PURL: "pkg:apk/alpine/musl@1.2.4-r2", License: "MIT"},
		},
	}

	data, err := GenerateSPDX(report)
	if err != nil {
		t.Fatalf("GenerateSPDX failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse generated SPDX JSON: %v", err)
	}

	if parsed["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion = %v; want SPDX-2.3", parsed["spdxVersion"])
	}

	packages, ok := parsed["packages"].([]any)
	if !ok || len(packages) != 2 {
		t.Fatalf("expected 2 packages in SPDX, got %d", len(packages))
	}

	relationships, ok := parsed["relationships"].([]any)
	if !ok || len(relationships) != 2 {
		t.Fatalf("expected 2 relationships in SPDX, got %d", len(relationships))
	}
}

func TestGenerateCycloneDX(t *testing.T) {
	report := &ScanReport{
		ID:        "01234567-89ab-cdef-0123-456789abcdef",
		ImageID:   "sha256:feedface",
		ImageName: "nginx:1.25-alpine",
		Digest:    "sha256:feedface",
		ScannedAt: time.Now().UTC(),
		Packages: []PackageInfo{
			{Name: "nginx", Version: "1.25.3", Type: PackageTypeAPK, PURL: "pkg:apk/alpine/nginx@1.25.3", License: "BSD-2-Clause"},
		},
		Vulnerabilities: []Vulnerability{
			{
				ID:           "CVE-2023-38545",
				Severity:     SeverityCritical,
				CVSS:         9.8,
				Package:      "nginx",
				FixedVersion: "1.25.4",
				Title:        "Test Vuln",
				Description:  "Heap buffer overflow test",
			},
		},
	}

	data, err := GenerateCycloneDX(report)
	if err != nil {
		t.Fatalf("GenerateCycloneDX failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse CycloneDX JSON: %v", err)
	}

	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v; want CycloneDX", parsed["bomFormat"])
	}
	if parsed["specVersion"] != "1.5" {
		t.Errorf("specVersion = %v; want 1.5", parsed["specVersion"])
	}

	vulns, ok := parsed["vulnerabilities"].([]any)
	if !ok || len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability in CycloneDX, got %d", len(vulns))
	}

	vulnObj := vulns[0].(map[string]any)
	if vulnObj["id"] != "CVE-2023-38545" {
		t.Errorf("vulnerability ID = %v; want CVE-2023-38545", vulnObj["id"])
	}
}

func TestGenerateSBOM_NilGuard(t *testing.T) {
	if _, err := GenerateSPDX(nil); err == nil {
		t.Errorf("expected error when generating SPDX with nil report")
	}
	if _, err := GenerateCycloneDX(nil); err == nil {
		t.Errorf("expected error when generating CycloneDX with nil report")
	}
}

func TestSanitizeSPDXID(t *testing.T) {
	dirty := "my-registry.io/org/app:v1.0.0@sha256:123"
	clean := sanitizeSPDXID(dirty)
	if strings.ContainsAny(clean, "/:@") {
		t.Errorf("sanitizeSPDXID failed to remove illegal characters: %s", clean)
	}
}
