package firewall

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PolicyAction defines the enforcement decision for matching packets.
type PolicyAction string

const (
	ActionAllow      PolicyAction = "ALLOW"
	ActionDrop       PolicyAction = "DROP"
	ActionReject     PolicyAction = "REJECT"
	ActionIsolate    PolicyAction = "ISOLATE"
	ActionQuarantine PolicyAction = "QUARANTINE"
	ActionThrottle   PolicyAction = "THROTTLE"
)

// TrafficDirection defines whether the rule applies to incoming or outgoing flows.
type TrafficDirection string

const (
	DirectionIngress TrafficDirection = "INGRESS"
	DirectionEgress  TrafficDirection = "EGRESS"
	DirectionBoth    TrafficDirection = "BOTH"
)

// Protocol specifies the layer 4 transport protocol.
type Protocol string

const (
	ProtocolTCP  Protocol = "TCP"
	ProtocolUDP  Protocol = "UDP"
	ProtocolICMP Protocol = "ICMP"
	ProtocolAny  Protocol = "ANY"
)

// IsolationLevel defines the network containment scope for a container.
type IsolationLevel string

const (
	IsolationNone           IsolationLevel = "NONE"
	IsolationPartial        IsolationLevel = "PARTIAL"          // External egress allowed, inter-container blocked
	IsolationStrictZero     IsolationLevel = "STRICT_ZEROTRUST" // All un-whitelisted inter-container flows blocked
	IsolationFullQuarantine IsolationLevel = "FULL_QUARANTINE"  // Completely severed from all network traffic
)

// FirewallRule defines a granular packet filtering and network control rule.
type FirewallRule struct {
	ID                string           `json:"id"`
	Name              string           `json:"name"`
	Description       string           `json:"description"`
	Priority          int              `json:"priority"` // 1 (highest) to 1000 (lowest)
	Enabled           bool             `json:"enabled"`
	Direction         TrafficDirection `json:"direction"`
	Action            PolicyAction     `json:"action"`
	Protocol          Protocol         `json:"protocol"`
	SourceCIDR        string           `json:"source_cidr"`          // e.g. "172.17.0.0/16", "10.0.0.1", or "*"
	SourcePort        string           `json:"source_port"`          // e.g. "80", "1000-2000", or "*"
	DestCIDR          string           `json:"dest_cidr"`            // destination CIDR/IP or "*"
	DestPort          string           `json:"dest_port"`            // destination port or "*"
	SourceContainerID string           `json:"source_container_id"` // matching container ID or "*"
	DestContainerID   string           `json:"dest_container_id"`   // matching container ID or "*"
	MatchedPackets    uint64           `json:"matched_packets"`
	MatchedBytes      uint64           `json:"matched_bytes"`
	CreatedAt         time.Time        `json:"created_at"`
	UpdatedAt         time.Time        `json:"updated_at"`

	parsedSrcIPNet *net.IPNet
	parsedDstIPNet *net.IPNet
	srcPortMin     int
	srcPortMax     int
	dstPortMin     int
	dstPortMax     int
}

// ContainerIsolationState tracks isolation posture and bandwidth throttling for a container.
type ContainerIsolationState struct {
	ContainerID             string         `json:"container_id"`
	ContainerName           string         `json:"container_name"`
	IsolationLevel          IsolationLevel `json:"isolation_level"`
	Reason                  string         `json:"reason"`
	IsolatedAt              time.Time      `json:"isolated_at"`
	AllowedPeers            []string       `json:"allowed_peers"` // whitelisted peer container IDs or names
	EgressBandwidthLimitBPS uint64         `json:"egress_bandwidth_limit_bps"`
	IngressBandwidthLimitBPS uint64        `json:"ingress_bandwidth_limit_bps"`
	CurrentEgressBPS        uint64         `json:"current_egress_bps"`
	CurrentIngressBPS       uint64         `json:"current_ingress_bps"`
	CurrentEgressPPS        uint64         `json:"current_egress_pps"`
	CurrentIngressPPS       uint64         `json:"current_ingress_pps"`
	DroppedPackets          uint64         `json:"dropped_packets"`
	DroppedBytes            uint64         `json:"dropped_bytes"`
	ThrottledEvents         uint64         `json:"throttled_events"`
	IsQuarantined           bool           `json:"is_quarantined"`
}

// DDoSAlertEvent captures detected anomalous traffic spikes and automatic remediations.
type DDoSAlertEvent struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	Direction     string    `json:"direction"` // "INGRESS" or "EGRESS"
	AlertReason   string    `json:"alert_reason"`
	ObservedPPS   uint64    `json:"observed_pps"`
	ThresholdPPS  uint64    `json:"threshold_pps"`
	ObservedBPS   uint64    `json:"observed_bps"`
	ThresholdBPS  uint64    `json:"threshold_bps"`
	ActionTaken   string    `json:"action_taken"` // "THROTTLED", "QUARANTINED", "ALERT_ONLY"
	Summary       string    `json:"summary"`
}

// BandwidthStats provides real-time container network throughput telemetry.
type BandwidthStats struct {
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	IngressBPS    uint64    `json:"ingress_bps"`
	EgressBPS     uint64    `json:"egress_bps"`
	IngressPPS    uint64    `json:"ingress_pps"`
	EgressPPS     uint64    `json:"egress_pps"`
	TotalBytesIn  uint64    `json:"total_bytes_in"`
	TotalBytesOut uint64    `json:"total_bytes_out"`
	LastSeen      time.Time `json:"last_seen"`
}

// FirewallConfig defines global operational parameters for packet filtering and isolation.
type FirewallConfig struct {
	Enabled             bool         `json:"enabled"`
	DefaultAction       PolicyAction `json:"default_action"` // "ALLOW" or "DROP"
	ZeroTrustEnabled    bool         `json:"zero_trust_enabled"`
	DDoSThresholdPPS    uint64       `json:"ddos_threshold_pps"`
	DDoSThresholdBPS    uint64       `json:"ddos_threshold_bps"`
	AutoQuarantineOnDDoS bool        `json:"auto_quarantine_on_ddos"`
	DDoSCooldownSec     int          `json:"ddos_cooldown_sec"`
	MaxRules            int          `json:"max_rules"`
	InspectionIntervalSec int        `json:"inspection_interval_sec"`
}

// DefaultFirewallConfig returns production-hardened defaults.
func DefaultFirewallConfig() FirewallConfig {
	return FirewallConfig{
		Enabled:               true,
		DefaultAction:         ActionAllow,
		ZeroTrustEnabled:      false,
		DDoSThresholdPPS:      50000,
		DDoSThresholdBPS:      104857600, // 100 MB/s
		AutoQuarantineOnDDoS:  true,
		DDoSCooldownSec:       60,
		MaxRules:              500,
		InspectionIntervalSec: 2,
	}
}

// FirewallStatus provides live diagnostic counters for Prometheus and dashboard.
type FirewallStatus struct {
	Enabled               bool      `json:"enabled"`
	ZeroTrustActive       bool      `json:"zero_trust_active"`
	TotalRules            int       `json:"total_rules"`
	ActiveRules           int       `json:"active_rules"`
	IsolatedContainers    int       `json:"isolated_containers"`
	QuarantinedContainers int       `json:"quarantined_containers"`
	TotalPacketsEvaluated uint64    `json:"total_packets_evaluated"`
	TotalPacketsAllowed   uint64    `json:"total_packets_allowed"`
	TotalPacketsBlocked   uint64    `json:"total_packets_blocked"`
	TotalPacketsThrottled uint64    `json:"total_packets_throttled"`
	TotalBytesEvaluated   uint64    `json:"total_bytes_evaluated"`
	TotalBytesBlocked     uint64    `json:"total_bytes_blocked"`
	ActiveDDoSAlerts      int       `json:"active_ddos_alerts"`
	LastEvaluationTime    time.Time `json:"last_evaluation_time"`
}

// PacketPayload represents a packet metadata snapshot evaluated by the firewall.
type PacketPayload struct {
	SourceContainerID string           `json:"source_container_id"`
	DestContainerID   string           `json:"dest_container_id"`
	SourceIP          string           `json:"source_ip"`
	SourcePort        int              `json:"source_port"`
	DestIP            string           `json:"dest_ip"`
	DestPort          int              `json:"dest_port"`
	Protocol          Protocol         `json:"protocol"`
	Direction         TrafficDirection `json:"direction"`
	PayloadLength     uint32           `json:"payload_length"`
}

// EvaluationResult contains the enforcement decision for a processed packet.
type EvaluationResult struct {
	Action         PolicyAction `json:"action"`
	MatchedRuleID  string       `json:"matched_rule_id,omitempty"`
	Reason         string       `json:"reason"`
	EvaluatedAt    time.Time    `json:"evaluated_at"`
	IsZeroTrustHit bool         `json:"is_zero_trust_hit"`
	IsQuarantined  bool         `json:"is_quarantined"`
	IsThrottled    bool         `json:"is_throttled"`
}

var ruleIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)

// Validate checks rule syntax, port ranges, and CIDR blocks.
func (r *FirewallRule) Validate() error {
	r.ID = strings.TrimSpace(r.ID)
	if r.ID == "" {
		return errors.New("rule id cannot be empty")
	}
	if !ruleIDRegex.MatchString(r.ID) {
		return fmt.Errorf("rule id %q contains invalid characters (must match ^[a-zA-Z0-9_-]+$)", r.ID)
	}
	if r.Priority < 1 || r.Priority > 1000 {
		return errors.New("priority must be between 1 (highest) and 1000 (lowest)")
	}

	switch r.Direction {
	case DirectionIngress, DirectionEgress, DirectionBoth:
	default:
		return fmt.Errorf("invalid direction: %s", r.Direction)
	}

	switch r.Action {
	case ActionAllow, ActionDrop, ActionReject, ActionIsolate, ActionQuarantine, ActionThrottle:
	default:
		return fmt.Errorf("invalid action: %s", r.Action)
	}

	switch r.Protocol {
	case ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolAny:
	default:
		return fmt.Errorf("invalid protocol: %s", r.Protocol)
	}

	if err := r.parseCIDRFields(); err != nil {
		return err
	}

	return r.parsePortRanges()
}

func (r *FirewallRule) parseCIDRFields() error {
	src := strings.TrimSpace(r.SourceCIDR)
	if src != "" && src != "*" {
		if !strings.Contains(src, "/") {
			if ip := net.ParseIP(src); ip != nil {
				if ip.To4() != nil {
					src += "/32"
				} else {
					src += "/128"
				}
			}
		}
		_, ipNet, err := net.ParseCIDR(src)
		if err != nil {
			return fmt.Errorf("invalid source_cidr %q: %w", r.SourceCIDR, err)
		}
		r.parsedSrcIPNet = ipNet
	}

	dst := strings.TrimSpace(r.DestCIDR)
	if dst != "" && dst != "*" {
		if !strings.Contains(dst, "/") {
			if ip := net.ParseIP(dst); ip != nil {
				if ip.To4() != nil {
					dst += "/32"
				} else {
					dst += "/128"
				}
			}
		}
		_, ipNet, err := net.ParseCIDR(dst)
		if err != nil {
			return fmt.Errorf("invalid dest_cidr %q: %w", r.DestCIDR, err)
		}
		r.parsedDstIPNet = ipNet
	}
	return nil
}

func (r *FirewallRule) parsePortRanges() error {
	var err error
	r.srcPortMin, r.srcPortMax, err = parsePortSpec(r.SourcePort)
	if err != nil {
		return fmt.Errorf("invalid source_port %q: %w", r.SourcePort, err)
	}

	r.dstPortMin, r.dstPortMax, err = parsePortSpec(r.DestPort)
	if err != nil {
		return fmt.Errorf("invalid dest_port %q: %w", r.DestPort, err)
	}
	return nil
}

func parsePortSpec(portStr string) (int, int, error) {
	p := strings.TrimSpace(portStr)
	if p == "" || p == "*" {
		return 0, 65535, nil
	}
	if strings.Contains(p, "-") {
		parts := strings.SplitN(p, "-", 2)
		minVal, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || minVal < 1 || minVal > 65535 {
			return 0, 0, fmt.Errorf("invalid range start port %q", parts[0])
		}
		maxVal, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || maxVal < 1 || maxVal > 65535 || maxVal < minVal {
			return 0, 0, fmt.Errorf("invalid range end port %q", parts[1])
		}
		return minVal, maxVal, nil
	}
	singleVal, err := strconv.Atoi(p)
	if err != nil || singleVal < 1 || singleVal > 65535 {
		return 0, 0, fmt.Errorf("port must be 1-65535, got %q", p)
	}
	return singleVal, singleVal, nil
}

// Validate checks configuration bounds.
func (c *FirewallConfig) Validate() error {
	if c.MaxRules < 10 || c.MaxRules > 5000 {
		return errors.New("max_rules must be between 10 and 5000")
	}
	if c.DDoSThresholdPPS < 100 {
		return errors.New("ddos_threshold_pps must be at least 100")
	}
	if c.DDoSThresholdBPS < 1024 {
		return errors.New("ddos_threshold_bps must be at least 1024 bytes/sec")
	}
	if c.DDoSCooldownSec < 5 || c.DDoSCooldownSec > 3600 {
		return errors.New("ddos_cooldown_sec must be between 5 and 3600 seconds")
	}
	if c.InspectionIntervalSec < 1 || c.InspectionIntervalSec > 60 {
		return errors.New("inspection_interval_sec must be between 1 and 60 seconds")
	}
	return nil
}
