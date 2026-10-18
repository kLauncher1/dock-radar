package scanner

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var spdxIDSanitizer = regexp.MustCompile(`[^a-zA-Z0-9.\-]+`)

// GenerateSPDX produces an official SPDX 2.3 JSON specification document from a scan report.
func GenerateSPDX(report *ScanReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("nil scan report provided")
	}

	docName := report.ImageName
	if docName == "" {
		docName = "container-image"
	}

	docNamespace := fmt.Sprintf("http://dock-radar.local/spdxdoc/%s-%s", sanitizeSPDXID(docName), report.ID)

	spdxPackages := make([]map[string]any, 0, len(report.Packages))
	relationships := make([]map[string]any, 0, len(report.Packages))

	for idx, pkg := range report.Packages {
		pkgSPDXID := fmt.Sprintf("SPDXRef-Package-%d-%s", idx+1, sanitizeSPDXID(pkg.Name))

		license := pkg.License
		if license == "" {
			license = "NOASSERTION"
		}

		externalRefs := []map[string]any{}
		if pkg.PURL != "" {
			externalRefs = append(externalRefs, map[string]any{
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceType":     "purl",
				"referenceLocator":  pkg.PURL,
			})
		}

		spdxPackages = append(spdxPackages, map[string]any{
			"SPDXID":           pkgSPDXID,
			"name":             pkg.Name,
			"versionInfo":      pkg.Version,
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed":    false,
			"licenseConcluded": license,
			"licenseDeclared":  license,
			"copyrightText":    "NOASSERTION",
			"externalRefs":     externalRefs,
		})

		relationships = append(relationships, map[string]any{
			"spdxElementId":      "SPDXRef-DOCUMENT",
			"relatedSpdxElement": pkgSPDXID,
			"relationshipType":   "DESCRIBES",
		})
	}

	doc := map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              docName,
		"documentNamespace": docNamespace,
		"creationInfo": map[string]any{
			"created": report.ScannedAt.UTC().Format(time.RFC3339),
			"creators": []string{
				"Tool: dock-radar-sbom-2.2.0",
				"Organization: Dock-Radar",
			},
		},
		"packages":      spdxPackages,
		"relationships": relationships,
	}

	return json.MarshalIndent(doc, "", "  ")
}

// GenerateCycloneDX produces an official CycloneDX 1.5 JSON specification document from a scan report.
func GenerateCycloneDX(report *ScanReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("nil scan report provided")
	}

	imgName := report.ImageName
	if imgName == "" {
		imgName = "container-image"
	}

	components := make([]map[string]any, 0, len(report.Packages))
	purlIndex := make(map[string]string) // pkgName -> purl

	for _, pkg := range report.Packages {
		purl := pkg.PURL
		if purl == "" {
			purl = FormatPURL(pkg.Type, "", pkg.Name, pkg.Version)
		}
		purlIndex[pkg.Name] = purl

		comp := map[string]any{
			"bom-ref": purl,
			"type":    "library",
			"name":    pkg.Name,
			"version": pkg.Version,
			"purl":    purl,
		}

		if pkg.License != "" {
			comp["licenses"] = []map[string]any{
				{
					"license": map[string]any{
						"id": pkg.License,
					},
				},
			}
		}

		components = append(components, comp)
	}

	// Map vulnerabilities
	vulnerabilities := make([]map[string]any, 0, len(report.Vulnerabilities))
	for _, vuln := range report.Vulnerabilities {
		affects := []map[string]any{}
		if purl, ok := purlIndex[vuln.Package]; ok {
			affects = append(affects, map[string]any{
				"ref": purl,
			})
		}

		vulnObj := map[string]any{
			"id": vuln.ID,
			"source": map[string]any{
				"name": "NVD",
				"url":  vuln.AdvisoryURL,
			},
			"ratings": []map[string]any{
				{
					"source": map[string]any{
						"name": "NVD",
					},
					"score":    vuln.CVSS,
					"severity": strings.ToLower(string(vuln.Severity)),
					"method":   "CVSSv31",
				},
			},
			"description": vuln.Description,
			"detail":      vuln.Title,
			"affects":     affects,
		}

		if vuln.FixedVersion != "" {
			vulnObj["recommendation"] = fmt.Sprintf("Upgrade %s to %s or higher", vuln.Package, vuln.FixedVersion)
		}

		vulnerabilities = append(vulnerabilities, vulnObj)
	}

	serialURN := fmt.Sprintf("urn:uuid:%s", report.ID)
	if !strings.Contains(report.ID, "-") {
		serialURN = fmt.Sprintf("urn:uuid:00000000-0000-0000-0000-%s", report.ID)
	}

	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"serialNumber": serialURN,
		"version":     1,
		"metadata": map[string]any{
			"timestamp": report.ScannedAt.UTC().Format(time.RFC3339),
			"tools": []map[string]any{
				{
					"vendor":  "Dock-Radar",
					"name":    "dock-radar-sbom",
					"version": "2.2.0",
				},
			},
			"component": map[string]any{
				"bom-ref": fmt.Sprintf("pkg:oci/%s", imgName),
				"type":    "container",
				"name":    imgName,
				"version": report.Digest,
			},
		},
		"components":      components,
		"vulnerabilities": vulnerabilities,
	}

	return json.MarshalIndent(doc, "", "  ")
}

func sanitizeSPDXID(s string) string {
	res := spdxIDSanitizer.ReplaceAllString(s, "-")
	return strings.Trim(res, "-")
}
