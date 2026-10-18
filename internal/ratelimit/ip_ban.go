package ratelimit

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// IPBanStore manages automated and manual IP bans, tracks violation frequency,
// and enforces cluster-wide abuse mitigation.
type IPBanStore struct {
	mu          sync.RWMutex
	bans        map[string]*IPBanRecord // Key: normalized IP string
	violations  map[string]*violationTracker
	banDuration time.Duration
	threshold   int
	autoBan     bool
}

type violationTracker struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
}

// NewIPBanStore creates an initialized IPBanStore.
func NewIPBanStore(threshold int, banDuration time.Duration, autoBan bool) *IPBanStore {
	if threshold <= 0 {
		threshold = 10
	}
	if banDuration <= 0 {
		banDuration = 15 * time.Minute
	}
	return &IPBanStore{
		bans:        make(map[string]*IPBanRecord),
		violations:  make(map[string]*violationTracker),
		banDuration: banDuration,
		threshold:   threshold,
		autoBan:     autoBan,
	}
}

// normalizeIP cleans and validates the given IP string. Returns normalized IP or error.
func normalizeIP(ipStr string) (string, error) {
	clean := strings.TrimSpace(ipStr)
	if clean == "" {
		return "", errors.New("empty IP address")
	}

	// Handle host:port case if passed
	if host, _, err := net.SplitHostPort(clean); err == nil {
		clean = host
	}

	parsed := net.ParseIP(clean)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP address format: %s", clean)
	}

	if parsed.IsLoopback() {
		return "", errors.New("loopback IP address cannot be banned")
	}

	return parsed.String(), nil
}

// IsBanned checks if an IP is currently banned. Returns (banned, banRecord).
func (s *IPBanStore) IsBanned(ipStr string) (bool, *IPBanRecord) {
	normalized, err := normalizeIP(ipStr)
	if err != nil {
		return false, nil
	}

	s.mu.RLock()
	record, exists := s.bans[normalized]
	s.mu.RUnlock()

	if !exists {
		return false, nil
	}

	now := time.Now()
	if now.After(record.ExpiresAt) {
		// Lazily clean up expired ban
		s.mu.Lock()
		delete(s.bans, normalized)
		s.mu.Unlock()
		return false, nil
	}

	return true, record
}

// RecordViolation registers an abuse violation (e.g. rate limit breach, repeated 401s).
// Automatically triggers an IP ban if threshold is exceeded and autoBan is enabled.
func (s *IPBanStore) RecordViolation(ipStr string, reason string) (banned bool, record *IPBanRecord) {
	normalized, err := normalizeIP(ipStr)
	if err != nil {
		return false, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already banned
	if existing, exists := s.bans[normalized]; exists && time.Now().Before(existing.ExpiresAt) {
		existing.ViolationCount++
		return true, existing
	}

	now := time.Now()
	tracker, exists := s.violations[normalized]
	if !exists || now.Sub(tracker.lastSeen) > 5*time.Minute {
		// Reset tracking window after 5 minutes of inactivity
		tracker = &violationTracker{
			count:     1,
			firstSeen: now,
			lastSeen:  now,
		}
		s.violations[normalized] = tracker
	} else {
		tracker.count++
		tracker.lastSeen = now
	}

	if s.autoBan && tracker.count >= s.threshold {
		banRecord := &IPBanRecord{
			IP:             normalized,
			Reason:         reason,
			ViolationCount: tracker.count,
			BannedAt:       now,
			ExpiresAt:      now.Add(s.banDuration),
			OriginNode:     "local",
			Active:         true,
		}
		s.bans[normalized] = banRecord
		delete(s.violations, normalized)
		return true, banRecord
	}

	return false, nil
}

// Ban manually bans an IP with the given parameters.
func (s *IPBanStore) Ban(ipStr string, reason string, duration time.Duration, originNode string) (*IPBanRecord, error) {
	normalized, err := normalizeIP(ipStr)
	if err != nil {
		return nil, err
	}

	if duration <= 0 {
		duration = s.banDuration
	}
	if reason == "" {
		reason = "manual administrative ban"
	}
	if originNode == "" {
		originNode = "local"
	}

	now := time.Now()
	record := &IPBanRecord{
		IP:             normalized,
		Reason:         reason,
		ViolationCount: 1,
		BannedAt:       now,
		ExpiresAt:      now.Add(duration),
		OriginNode:     originNode,
		Active:         true,
	}

	s.mu.Lock()
	s.bans[normalized] = record
	delete(s.violations, normalized)
	s.mu.Unlock()

	return record, nil
}

// Unban removes an IP from the ban list.
func (s *IPBanStore) Unban(ipStr string) bool {
	normalized, err := normalizeIP(ipStr)
	if err != nil {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.bans[normalized]; exists {
		delete(s.bans, normalized)
		return true
	}
	return false
}

// ActiveBans returns a list of all currently active IP bans.
func (s *IPBanStore) ActiveBans() []*IPBanRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	results := make([]*IPBanRecord, 0, len(s.bans))
	for _, record := range s.bans {
		if now.Before(record.ExpiresAt) {
			results = append(results, record)
		}
	}
	return results
}

// Count returns the number of active banned IPs.
func (s *IPBanStore) Count() int {
	return len(s.ActiveBans())
}

// SweepExpired purges expired bans and old violation records from memory.
func (s *IPBanStore) SweepExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	purged := 0

	for ip, record := range s.bans {
		if now.After(record.ExpiresAt) {
			delete(s.bans, ip)
			purged++
		}
	}

	for ip, tracker := range s.violations {
		if now.Sub(tracker.lastSeen) > 10*time.Minute {
			delete(s.violations, ip)
		}
	}

	return purged
}
