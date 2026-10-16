package ebpf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
)

// SecurityEngine evaluates system call activity against behavioral threat rules.
type SecurityEngine struct {
	mu           sync.RWMutex
	rules        []SecurityRule
	alerts       []SecurityAlert
	maxAlerts    int
	totalAlerts  uint64
	autoWebhook  bool
	dispatcher   *alert.Dispatcher
}

// NewSecurityEngine constructs a security anomaly engine with initial rules.
func NewSecurityEngine(rules []SecurityRule, maxAlerts int, autoWebhook bool, dispatcher *alert.Dispatcher) *SecurityEngine {
	if maxAlerts <= 0 {
		maxAlerts = 500
	}
	se := &SecurityEngine{
		rules:       make([]SecurityRule, len(rules)),
		alerts:      make([]SecurityAlert, 0, maxAlerts),
		maxAlerts:   maxAlerts,
		autoWebhook: autoWebhook,
		dispatcher:  dispatcher,
	}

	for i, r := range rules {
		se.rules[i] = r
		_ = se.rules[i].Compile()
	}

	return se
}

func generateAlertID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Evaluate evaluates a single system call event against all enabled security rules.
func (se *SecurityEngine) Evaluate(event SyscallEvent) *SecurityAlert {
	se.mu.RLock()
	rules := make([]SecurityRule, len(se.rules))
	copy(rules, se.rules)
	autoWebhook := se.autoWebhook
	se.mu.RUnlock()

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Check container exclusions
		excluded := false
		for _, exc := range rule.ExcludedContainers {
			if exc == event.ContainerID || exc == event.ContainerName {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Match syscall identifier
		if rule.Syscall != "*" && !strings.EqualFold(rule.Syscall, event.Syscall) {
			continue
		}

		// Match pattern against command name and arguments
		matched := false
		matchedTarget := ""
		if rule.Matches(event.Comm) {
			matched = true
			matchedTarget = event.Comm
		} else {
			for _, arg := range event.Args {
				if rule.Matches(arg) {
					matched = true
					matchedTarget = arg
					break
				}
			}
		}

		if matched {
			alertObj := se.recordAlert(event, rule, matchedTarget)

			// Dispatch webhook asynchronously if enabled and severe
			if autoWebhook && se.dispatcher != nil && (rule.Severity == SeverityCritical || rule.Severity == SeverityHigh) {
				go se.dispatchWebhook(alertObj)
			}

			return &alertObj
		}
	}

	return nil
}

func (se *SecurityEngine) recordAlert(event SyscallEvent, rule SecurityRule, evidence string) SecurityAlert {
	mitigation := "Inspect container process tree and review image security posture."
	switch rule.ID {
	case "sec-rule-shell-exec":
		mitigation = "Verify whether container is running in production with read-only rootfs; isolate shell binaries."
	case "sec-rule-priv-escalate":
		mitigation = "Enforce security_opt: no-new-privileges:true and drop CAP_SETUID/CAP_SETGID."
	case "sec-rule-ptrace-inject":
		mitigation = "Drop CAP_SYS_PTRACE capability and verify whether debugging agent is authorized."
	case "sec-rule-sensitive-file":
		mitigation = "Audit volume mount declarations and prevent root filesystem host-passthrough."
	case "sec-rule-docker-socket":
		mitigation = "Revoke /var/run/docker.sock mount from container configuration immediately."
	case "sec-rule-cryptominer-outbound":
		mitigation = "Terminate suspect outbound connections and quarantine container instance."
	}

	alertObj := SecurityAlert{
		ID:            generateAlertID(),
		Timestamp:     time.Now().UTC(),
		ContainerID:   event.ContainerID,
		ContainerName: event.ContainerName,
		RuleID:        rule.ID,
		RuleName:      rule.Name,
		Severity:      rule.Severity,
		Summary:       fmt.Sprintf("%s in container %q (PID %d)", rule.Name, event.ContainerName, event.PID),
		Syscall:       event.Syscall,
		PID:           event.PID,
		Comm:          event.Comm,
		Evidence:      evidence,
		Mitigation:    mitigation,
	}

	se.mu.Lock()
	defer se.mu.Unlock()

	atomic.AddUint64(&se.totalAlerts, 1)

	// Circular FIFO buffer
	if len(se.alerts) >= se.maxAlerts {
		se.alerts = se.alerts[1:]
	}
	se.alerts = append(se.alerts, alertObj)

	return alertObj
}

func (se *SecurityEngine) dispatchWebhook(secAlert SecurityAlert) {
	level := alert.LevelWarning
	if secAlert.Severity == SeverityCritical {
		level = alert.LevelCritical
	}

	evt := alert.Event{
		ID:        secAlert.ID,
		Timestamp: secAlert.Timestamp,
		Level:     level,
		Source:    fmt.Sprintf("ebpf:%s", secAlert.ContainerName),
		EventType: "security_anomaly",
		Message:   fmt.Sprintf("[%s] %s: %s (Evidence: %s)", strings.ToUpper(string(secAlert.Severity)), secAlert.RuleName, secAlert.Summary, secAlert.Evidence),
		Details: map[string]any{
			"container_id": secAlert.ContainerID,
			"pid":          secAlert.PID,
			"comm":         secAlert.Comm,
			"syscall":      secAlert.Syscall,
			"mitigation":   secAlert.Mitigation,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = se.dispatcher.Dispatch(ctx, evt)
}

// RecentAlerts returns the most recent alerts matching criteria.
func (se *SecurityEngine) RecentAlerts(limit int, severity string, containerID string) []SecurityAlert {
	se.mu.RLock()
	defer se.mu.RUnlock()

	matched := make([]SecurityAlert, 0, len(se.alerts))
	for i := len(se.alerts) - 1; i >= 0; i-- {
		a := se.alerts[i]
		if severity != "" && !strings.EqualFold(string(a.Severity), severity) {
			continue
		}
		if containerID != "" && a.ContainerID != containerID {
			continue
		}
		matched = append(matched, a)
		if limit > 0 && len(matched) >= limit {
			break
		}
	}
	return matched
}

// GetRules returns a copy of current rules.
func (se *SecurityEngine) GetRules() []SecurityRule {
	se.mu.RLock()
	defer se.mu.RUnlock()

	rulesCopy := make([]SecurityRule, len(se.rules))
	copy(rulesCopy, se.rules)
	return rulesCopy
}

// UpdateRules replaces the active ruleset after compiling and validating patterns.
func (se *SecurityEngine) UpdateRules(rules []SecurityRule) error {
	compiled := make([]SecurityRule, len(rules))
	for i, r := range rules {
		if strings.TrimSpace(r.ID) == "" {
			return errors.New("rule ID cannot be empty")
		}
		compiled[i] = r
		if err := compiled[i].Compile(); err != nil {
			return err
		}
	}

	se.mu.Lock()
	defer se.mu.Unlock()
	se.rules = compiled
	return nil
}

// ToggleRule enables or disables a rule by ID.
func (se *SecurityEngine) ToggleRule(ruleID string, enabled bool) error {
	se.mu.Lock()
	defer se.mu.Unlock()

	for i := range se.rules {
		if se.rules[i].ID == ruleID {
			se.rules[i].Enabled = enabled
			return nil
		}
	}
	return fmt.Errorf("rule %q not found", ruleID)
}

// TotalAlerts returns the cumulative number of alerts generated.
func (se *SecurityEngine) TotalAlerts() uint64 {
	return atomic.LoadUint64(&se.totalAlerts)
}

// ClearAlerts empties the active alert log.
func (se *SecurityEngine) ClearAlerts() {
	se.mu.Lock()
	defer se.mu.Unlock()
	se.alerts = make([]SecurityAlert, 0, se.maxAlerts)
}
