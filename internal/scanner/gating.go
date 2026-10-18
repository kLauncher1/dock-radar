package scanner

import (
	"fmt"
	"strings"
	"time"
)

// EvaluateGating evaluates a container image scan report against deployment security policies.
func EvaluateGating(report *ScanReport, policy GatingPolicy) GatingResult {
	if report == nil {
		return GatingResult{
			Status:      GatingStatusBlocked,
			Passed:      false,
			Reason:      "No scan report available for security gating evaluation",
			EvaluatedAt: time.Now().UTC(),
		}
	}

	whitelistMap := make(map[string]bool, len(policy.WhitelistCVEs))
	for _, cve := range policy.WhitelistCVEs {
		whitelistMap[strings.ToUpper(strings.TrimSpace(cve))] = true
	}

	var activeCritical, activeHigh, activeMed, activeLow int
	var violations []string

	for _, vuln := range report.Vulnerabilities {
		cveUpper := strings.ToUpper(strings.TrimSpace(vuln.ID))
		if whitelistMap[cveUpper] {
			continue // Whitelisted
		}

		switch vuln.Severity {
		case SeverityCritical:
			activeCritical++
		case SeverityHigh:
			activeHigh++
		case SeverityMedium:
			activeMed++
		case SeverityLow:
			activeLow++
		}

		// Check FailOnSeverity threshold
		if policy.FailOnSeverity != "" && vuln.Severity.Weight() >= policy.FailOnSeverity.Weight() {
			violations = append(violations, fmt.Sprintf("%s (%s) exceeds failure severity threshold %s", vuln.ID, vuln.Severity, policy.FailOnSeverity))
		}
	}

	// Check MaxCritical
	if activeCritical > policy.MaxCritical {
		violations = append(violations, fmt.Sprintf("Critical vulnerability count (%d) exceeds permitted threshold (%d)", activeCritical, policy.MaxCritical))
	}

	// Check MaxHigh
	if activeHigh > policy.MaxHigh {
		violations = append(violations, fmt.Sprintf("High vulnerability count (%d) exceeds permitted threshold (%d)", activeHigh, policy.MaxHigh))
	}

	// Check AllowedLicenses if configured
	if len(policy.AllowedLicenses) > 0 {
		allowedMap := make(map[string]bool, len(policy.AllowedLicenses))
		for _, l := range policy.AllowedLicenses {
			allowedMap[strings.ToLower(strings.TrimSpace(l))] = true
		}

		for _, pkg := range report.Packages {
			if pkg.License == "" || pkg.License == "NOASSERTION" {
				continue
			}
			if !allowedMap[strings.ToLower(strings.TrimSpace(pkg.License))] {
				violations = append(violations, fmt.Sprintf("Package %s uses non-whitelisted license: %s", pkg.Name, pkg.License))
			}
		}
	}

	now := time.Now().UTC()
	if len(violations) > 0 {
		return GatingResult{
			Status:      GatingStatusBlocked,
			Passed:      false,
			Reason:      fmt.Sprintf("Deployment blocked: %d policy violation(s) detected", len(violations)),
			Violations:  violations,
			EvaluatedAt: now,
		}
	}

	// If no blocking violations but some high/medium present, mark as warning or pass
	if activeHigh > 0 || activeMed > 5 {
		return GatingResult{
			Status:      GatingStatusWarning,
			Passed:      true,
			Reason:      "Deployment passed with security warnings (elevated CVE count)",
			EvaluatedAt: now,
		}
	}

	return GatingResult{
		Status:      GatingStatusPass,
		Passed:      true,
		Reason:      "Deployment security gating passed all compliance checks",
		EvaluatedAt: now,
	}
}
