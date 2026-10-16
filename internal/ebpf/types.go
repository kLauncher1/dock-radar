package ebpf

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ProbeMode identifies the telemetry acquisition strategy.
type ProbeMode string

const (
	// ProbeModeNative indicates native eBPF kprobe/tracepoint hooks are active.
	ProbeModeNative ProbeMode = "ebpf_native"
	// ProbeModeProcfs indicates kernel socket inspection via /proc/net and netlink fallback.
	ProbeModeProcfs ProbeMode = "procfs_socket"
	// ProbeModeSynthetic indicates portable high-fidelity telemetry engine for non-Linux or containerized dev hosts.
	ProbeModeSynthetic ProbeMode = "synthetic_trace"
)

// Severity defines the threat level of a kernel security anomaly.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// SocketFlow represents an active network flow traced for a container.
type SocketFlow struct {
	ID            string    `json:"id"`
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	Protocol      string    `json:"protocol"` // "TCP" or "UDP"
	LocalAddr     string    `json:"local_addr"`
	RemoteAddr    string    `json:"remote_addr"`
	State         string    `json:"state"` // e.g. "ESTABLISHED", "LISTEN", "TIME_WAIT"
	BytesSent     uint64    `json:"bytes_sent"`
	BytesRecv     uint64    `json:"bytes_recv"`
	PacketsSent   uint64    `json:"packets_sent"`
	PacketsRecv   uint64    `json:"packets_recv"`
	Retransmits   uint32    `json:"retransmits"`
	RTTMillis     float64   `json:"rtt_millis"`
	PID           int       `json:"pid,omitempty"`
	Comm          string    `json:"comm,omitempty"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

// FlowFilter specifies querying constraints for active flows.
type FlowFilter struct {
	ContainerID string `json:"container_id,omitempty"`
	State       string `json:"state,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Limit       int    `json:"limit,omitempty"`
}

// SyscallEvent encapsulates a traced low-level system call event.
type SyscallEvent struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	PID           int       `json:"pid"`
	Syscall       string    `json:"syscall"`
	Comm          string    `json:"comm"`
	Args          []string  `json:"args,omitempty"`
	ReturnValue   int64     `json:"return_value"`
}

// SecurityAlert represents a triggered security anomaly in container execution.
type SecurityAlert struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	RuleID        string    `json:"rule_id"`
	RuleName      string    `json:"rule_name"`
	Severity      Severity  `json:"severity"`
	Summary       string    `json:"summary"`
	Syscall       string    `json:"syscall"`
	PID           int       `json:"pid"`
	Comm          string    `json:"comm"`
	Evidence      string    `json:"evidence"`
	Mitigation    string    `json:"mitigation"`
}

// SecurityRule configures anomaly detection patterns.
type SecurityRule struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	Severity           Severity `json:"severity"`
	Enabled            bool     `json:"enabled"`
	Syscall            string   `json:"syscall"` // e.g. "execve", "ptrace", "*"
	Pattern            string   `json:"pattern"` // regex pattern matching comm or args
	ExcludedContainers []string `json:"excluded_containers,omitempty"`
	regex              *regexp.Regexp
}

// Compile compiles the rule's regex pattern if not already compiled.
func (r *SecurityRule) Compile() error {
	if r.Pattern == "" {
		r.regex = nil
		return nil
	}
	compiled, err := regexp.Compile(r.Pattern)
	if err != nil {
		return fmt.Errorf("invalid regex in rule %q: %w", r.ID, err)
	}
	r.regex = compiled
	return nil
}

// Matches tests whether a comm string or arg matches the rule.
func (r *SecurityRule) Matches(target string) bool {
	if r.regex == nil {
		if err := r.Compile(); err != nil {
			return false
		}
	}
	if r.regex == nil {
		return false
	}
	return r.regex.MatchString(target)
}

// EBPFConfig configures telemetry probing behavior.
type EBPFConfig struct {
	Enabled             bool           `json:"enabled"`
	Mode                ProbeMode      `json:"mode"`
	SamplingIntervalSec int            `json:"sampling_interval_sec"`
	MaxTrackedFlows     int            `json:"max_tracked_flows"`
	MaxRecentAlerts     int            `json:"max_recent_alerts"`
	AutoAlertWebhook    bool           `json:"auto_alert_webhook"`
	SecurityRules       []SecurityRule `json:"security_rules"`
}

// DefaultEBPFConfig returns balanced production defaults.
func DefaultEBPFConfig() EBPFConfig {
	return EBPFConfig{
		Enabled:             true,
		Mode:                ProbeModeProcfs,
		SamplingIntervalSec: 2,
		MaxTrackedFlows:     2000,
		MaxRecentAlerts:     500,
		AutoAlertWebhook:    true,
		SecurityRules:       DefaultSecurityRules(),
	}
}

// Validate checks configuration values against allowable limits.
func (c *EBPFConfig) Validate() error {
	if c.SamplingIntervalSec < 1 || c.SamplingIntervalSec > 60 {
		return errors.New("sampling_interval_sec must be between 1 and 60 seconds")
	}
	if c.MaxTrackedFlows < 100 || c.MaxTrackedFlows > 20000 {
		return errors.New("max_tracked_flows must be between 100 and 20000")
	}
	if c.MaxRecentAlerts < 50 || c.MaxRecentAlerts > 5000 {
		return errors.New("max_recent_alerts must be between 50 and 5000")
	}
	for i := range c.SecurityRules {
		rule := &c.SecurityRules[i]
		if strings.TrimSpace(rule.ID) == "" {
			return errors.New("security rule ID cannot be empty")
		}
		if err := rule.Compile(); err != nil {
			return err
		}
	}
	return nil
}

// EBPFStatus reports runtime engine telemetry.
type EBPFStatus struct {
	Enabled              bool      `json:"enabled"`
	Mode                 ProbeMode `json:"mode"`
	KernelVersion        string    `json:"kernel_version"`
	ActiveFlows          int       `json:"active_flows"`
	TotalFlowsTracked    uint64    `json:"total_flows_tracked"`
	TotalSyscallsTraced  uint64    `json:"total_syscalls_traced"`
	TotalSecurityAlerts  uint64    `json:"total_security_alerts"`
	BytesIngressTotal    uint64    `json:"bytes_ingress_total"`
	BytesEgressTotal     uint64    `json:"bytes_egress_total"`
	MonitoredContainers  int       `json:"monitored_containers"`
	CPUOverheadPercent   float64   `json:"cpu_overhead_percent"`
	LastProbeTime        time.Time `json:"last_probe_time"`
}

// DefaultSecurityRules defines foundational container security anomaly rules.
func DefaultSecurityRules() []SecurityRule {
	return []SecurityRule{
		{
			ID:          "sec-rule-shell-exec",
			Name:        "Unexpected Interactive Shell Execution",
			Description: "Detects interactive shell invocation (sh/bash/zsh) inside production container workloads",
			Severity:    SeverityHigh,
			Enabled:     true,
			Syscall:     "execve",
			Pattern:     `(?i)(/bin/)?(sh|bash|ash|zsh|dash)$`,
		},
		{
			ID:          "sec-rule-priv-escalate",
			Name:        "Privilege Escalation & Capability Tampering",
			Description: "Traces setuid, setgid, or capset invocations attempting privilege escalation",
			Severity:    SeverityCritical,
			Enabled:     true,
			Syscall:     "setuid",
			Pattern:     `.*`,
		},
		{
			ID:          "sec-rule-ptrace-inject",
			Name:        "Process Memory Inspection & Injection",
			Description: "Identifies ptrace or process_vm_writev syscalls targeting foreign container processes",
			Severity:    SeverityHigh,
			Enabled:     true,
			Syscall:     "ptrace",
			Pattern:     `.*`,
		},
		{
			ID:          "sec-rule-sensitive-file",
			Name:        "Sensitive Host Credential Read Attempt",
			Description: "Flags attempts to read sensitive host credentials (/etc/shadow, /root/.ssh, id_rsa)",
			Severity:    SeverityCritical,
			Enabled:     true,
			Syscall:     "openat",
			Pattern:     `(?i)(/etc/shadow|/etc/sudoers|\.ssh/(id_rsa|id_ed25519)|authorized_keys)`,
		},
		{
			ID:          "sec-rule-docker-socket",
			Name:        "Container Escape via Docker Socket",
			Description: "Detects unauthorized connection or syscalls directed at /var/run/docker.sock",
			Severity:    SeverityCritical,
			Enabled:     true,
			Syscall:     "connect",
			Pattern:     `(?i)docker\.sock`,
		},
		{
			ID:          "sec-rule-cryptominer-outbound",
			Name:        "Suspected Outbound Mining Pool Flow",
			Description: "Traces network connections to common crypto mining pool ports (3333, 4444, 5555, 7777, 9999)",
			Severity:    SeverityHigh,
			Enabled:     true,
			Syscall:     "connect",
			Pattern:     `:(3333|4444|5555|7777|9999)$`,
		},
	}
}
