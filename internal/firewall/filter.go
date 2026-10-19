package firewall

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PacketFilter evaluates network packet payloads against ordered firewall rules.
type PacketFilter struct {
	mu            sync.RWMutex
	rules         map[string]*FirewallRule
	sortedRules   []*FirewallRule
	maxRules      int
	defaultAction PolicyAction
}

// NewPacketFilter initializes a packet filter with default rule capacity.
func NewPacketFilter(maxRules int, defaultAction PolicyAction) *PacketFilter {
	if maxRules <= 0 {
		maxRules = 500
	}
	if defaultAction == "" {
		defaultAction = ActionAllow
	}
	return &PacketFilter{
		rules:         make(map[string]*FirewallRule),
		sortedRules:   make([]*FirewallRule, 0),
		maxRules:      maxRules,
		defaultAction: defaultAction,
	}
}

// AddRule validates and inserts a new rule into the filter.
func (pf *PacketFilter) AddRule(rule FirewallRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}

	pf.mu.Lock()
	defer pf.mu.Unlock()

	if _, exists := pf.rules[rule.ID]; exists {
		return fmt.Errorf("rule with ID %q already exists", rule.ID)
	}

	if len(pf.rules) >= pf.maxRules {
		return fmt.Errorf("maximum rule limit (%d) reached", pf.maxRules)
	}

	now := time.Now().UTC()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	ruleCopy := rule
	pf.rules[rule.ID] = &ruleCopy
	pf.rebuildSortedLocked()
	return nil
}

// UpdateRule modifies an existing rule.
func (pf *PacketFilter) UpdateRule(rule FirewallRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}

	pf.mu.Lock()
	defer pf.mu.Unlock()

	existing, exists := pf.rules[rule.ID]
	if !exists {
		return fmt.Errorf("rule with ID %q not found", rule.ID)
	}

	rule.CreatedAt = existing.CreatedAt
	rule.UpdatedAt = time.Now().UTC()
	rule.MatchedPackets = atomic.LoadUint64(&existing.MatchedPackets)
	rule.MatchedBytes = atomic.LoadUint64(&existing.MatchedBytes)

	ruleCopy := rule
	pf.rules[rule.ID] = &ruleCopy
	pf.rebuildSortedLocked()
	return nil
}

// DeleteRule removes a rule by ID.
func (pf *PacketFilter) DeleteRule(ruleID string) error {
	pf.mu.Lock()
	defer pf.mu.Unlock()

	if _, exists := pf.rules[ruleID]; !exists {
		return fmt.Errorf("rule with ID %q not found", ruleID)
	}

	delete(pf.rules, ruleID)
	pf.rebuildSortedLocked()
	return nil
}

// GetRule retrieves a rule by ID.
func (pf *PacketFilter) GetRule(ruleID string) (FirewallRule, bool) {
	pf.mu.RLock()
	defer pf.mu.RUnlock()

	r, exists := pf.rules[ruleID]
	if !exists {
		return FirewallRule{}, false
	}
	res := *r
	res.MatchedPackets = atomic.LoadUint64(&r.MatchedPackets)
	res.MatchedBytes = atomic.LoadUint64(&r.MatchedBytes)
	return res, true
}

// ListRules returns all rules sorted by priority.
func (pf *PacketFilter) ListRules() []FirewallRule {
	pf.mu.RLock()
	defer pf.mu.RUnlock()

	res := make([]FirewallRule, 0, len(pf.sortedRules))
	for _, r := range pf.sortedRules {
		copyRule := *r
		copyRule.MatchedPackets = atomic.LoadUint64(&r.MatchedPackets)
		copyRule.MatchedBytes = atomic.LoadUint64(&r.MatchedBytes)
		res = append(res, copyRule)
	}
	return res
}

// Evaluate matches a packet against active rules in priority order.
func (pf *PacketFilter) Evaluate(p PacketPayload) EvaluationResult {
	pf.mu.RLock()
	defer pf.mu.RUnlock()

	srcIP := net.ParseIP(strings.TrimSpace(p.SourceIP))
	dstIP := net.ParseIP(strings.TrimSpace(p.DestIP))

	for _, rule := range pf.sortedRules {
		if !rule.Enabled {
			continue
		}

		// Direction check
		if rule.Direction != DirectionBoth && p.Direction != "" && rule.Direction != p.Direction {
			continue
		}

		// Protocol check
		if rule.Protocol != ProtocolAny && p.Protocol != "" && rule.Protocol != p.Protocol {
			continue
		}

		// Container ID matching
		if rule.SourceContainerID != "" && rule.SourceContainerID != "*" && p.SourceContainerID != "" {
			if !matchesContainer(rule.SourceContainerID, p.SourceContainerID) {
				continue
			}
		}
		if rule.DestContainerID != "" && rule.DestContainerID != "*" && p.DestContainerID != "" {
			if !matchesContainer(rule.DestContainerID, p.DestContainerID) {
				continue
			}
		}

		// IP CIDR matching
		if rule.parsedSrcIPNet != nil && srcIP != nil {
			if !rule.parsedSrcIPNet.Contains(srcIP) {
				continue
			}
		}
		if rule.parsedDstIPNet != nil && dstIP != nil {
			if !rule.parsedDstIPNet.Contains(dstIP) {
				continue
			}
		}

		// Port range matching
		if p.SourcePort > 0 && (p.SourcePort < rule.srcPortMin || p.SourcePort > rule.srcPortMax) {
			continue
		}
		if p.DestPort > 0 && (p.DestPort < rule.dstPortMin || p.DestPort > rule.dstPortMax) {
			continue
		}

		// Rule matched! Increment atomic counters
		atomic.AddUint64(&rule.MatchedPackets, 1)
		atomic.AddUint64(&rule.MatchedBytes, uint64(p.PayloadLength))

		return EvaluationResult{
			Action:        rule.Action,
			MatchedRuleID: rule.ID,
			Reason:        fmt.Sprintf("Matched rule %s (%s)", rule.ID, rule.Name),
			EvaluatedAt:   time.Now().UTC(),
		}
	}

	return EvaluationResult{
		Action:      pf.defaultAction,
		Reason:      fmt.Sprintf("Default firewall policy (%s)", pf.defaultAction),
		EvaluatedAt: time.Now().UTC(),
	}
}

// SetDefaultAction updates the default fallback policy.
func (pf *PacketFilter) SetDefaultAction(action PolicyAction) error {
	switch action {
	case ActionAllow, ActionDrop:
		pf.mu.Lock()
		pf.defaultAction = action
		pf.mu.Unlock()
		return nil
	default:
		return errors.New("default action must be either ALLOW or DROP")
	}
}

func (pf *PacketFilter) rebuildSortedLocked() {
	pf.sortedRules = make([]*FirewallRule, 0, len(pf.rules))
	for _, r := range pf.rules {
		pf.sortedRules = append(pf.sortedRules, r)
	}

	sort.Slice(pf.sortedRules, func(i, j int) bool {
		if pf.sortedRules[i].Priority != pf.sortedRules[j].Priority {
			return pf.sortedRules[i].Priority < pf.sortedRules[j].Priority
		}
		return pf.sortedRules[i].ID < pf.sortedRules[j].ID
	})
}

func matchesContainer(pattern, target string) bool {
	if pattern == "*" || pattern == target {
		return true
	}
	if strings.HasPrefix(target, pattern) || strings.HasPrefix(pattern, target) {
		return true
	}
	return false
}
