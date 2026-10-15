package mesh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// GossipState represents the SWIM failure detector state of a node.
type GossipState string

const (
	GossipStateAlive   GossipState = "alive"
	GossipStateSuspect GossipState = "suspect"
	GossipStateDead    GossipState = "dead"
)

const (
	DefaultGossipPingInterval = 2 * time.Second
	DefaultGossipPingTimeout  = 800 * time.Millisecond
	DefaultGossipSuspectLimit = 6 * time.Second
	DefaultGossipKIndirect    = 3
	MaxGossipPayloadBytes     = 256 * 1024
)

// GossipMemberDigest represents a lightweight member state update for piggybacking.
type GossipMemberDigest struct {
	NodeID      string      `json:"node_id"`
	NodeName    string      `json:"node_name"`
	Address     string      `json:"address"`
	State       GossipState `json:"state"`
	Incarnation uint64      `json:"incarnation"`
}

// GossipMember holds the local view of an individual cluster member's health.
type GossipMember struct {
	NodeID       string      `json:"node_id"`
	NodeName     string      `json:"node_name"`
	Address      string      `json:"address"`
	State        GossipState `json:"state"`
	Incarnation  uint64      `json:"incarnation"`
	LastSeen     time.Time   `json:"last_seen"`
	SuspectSince time.Time   `json:"suspect_since,omitempty"`
	LatencyMs    int64       `json:"latency_ms"`
}

// GossipMessage models the structured protocol packet exchanged between peers.
type GossipMessage struct {
	Type        string               `json:"type"` // "ping", "ack", "ping_req"
	SenderID    string               `json:"sender_id"`
	SenderName  string               `json:"sender_name"`
	SenderAddr  string               `json:"sender_addr"`
	TargetID    string               `json:"target_id,omitempty"`
	Incarnation uint64               `json:"incarnation"`
	Members     []GossipMemberDigest `json:"members,omitempty"`
	Timestamp   int64                `json:"timestamp"`
}

// GossipConfig specifies runtime parameters for SWIM failure detection.
type GossipConfig struct {
	PingInterval   time.Duration `json:"ping_interval"`
	PingTimeout    time.Duration `json:"ping_timeout"`
	SuspectTimeout time.Duration `json:"suspect_timeout"`
	KIndirect      int           `json:"k_indirect"`
	HTTPClient     *http.Client  `json:"-"`
	AuthToken      string        `json:"-"`
}

// GossipSummary reports aggregate metrics and state counts of the gossip engine.
type GossipSummary struct {
	LocalID         string `json:"local_id"`
	LocalName       string `json:"local_name"`
	Incarnation     uint64 `json:"incarnation"`
	TotalMembers    int    `json:"total_members"`
	AliveMembers    int    `json:"alive_members"`
	SuspectMembers  int    `json:"suspect_members"`
	DeadMembers     int    `json:"dead_members"`
	MessagesSent    uint64 `json:"messages_sent"`
	MessagesRecv    uint64 `json:"messages_recv"`
	SuspectTimeouts uint64 `json:"suspect_timeouts"`
}

// GossipEngine orchestrates SWIM failure detection, state dissemination, and incarnation refutation.
type GossipEngine struct {
	mu              sync.RWMutex
	localID         string
	localName       string
	localAddr       string
	incarnation     uint64
	registry        *Registry
	cfg             GossipConfig
	members         map[string]*GossipMember
	stopCh          chan struct{}
	stopOnce        sync.Once
	messagesSent    uint64
	messagesRecv    uint64
	suspectTimeouts uint64
}

// NewGossipEngine initializes a SWIM gossip protocol engine with safe defaults.
func NewGossipEngine(localID, localName, localAddr string, reg *Registry, cfg GossipConfig) *GossipEngine {
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = DefaultGossipPingInterval
	}
	if cfg.PingTimeout <= 0 {
		cfg.PingTimeout = DefaultGossipPingTimeout
	}
	if cfg.SuspectTimeout <= 0 {
		cfg.SuspectTimeout = DefaultGossipSuspectLimit
	}
	if cfg.KIndirect <= 0 {
		cfg.KIndirect = DefaultGossipKIndirect
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.PingTimeout}
	}

	engine := &GossipEngine{
		localID:     localID,
		localName:   localName,
		localAddr:   localAddr,
		incarnation: 0,
		registry:    reg,
		cfg:         cfg,
		members:     make(map[string]*GossipMember),
		stopCh:      make(chan struct{}),
	}

	// Register local node as alive with incarnation 0
	engine.members[localID] = &GossipMember{
		NodeID:      localID,
		NodeName:    localName,
		Address:     localAddr,
		State:       GossipStateAlive,
		Incarnation: 0,
		LastSeen:    time.Now().UTC(),
	}

	return engine
}

// Start begins the recurring SWIM ping and suspect evaluation loops.
func (g *GossipEngine) Start(ctx context.Context) {
	go g.pingLoop(ctx)
	go g.suspectWatchdog(ctx)
}

// Stop cleanly terminates the gossip engine.
func (g *GossipEngine) Stop() {
	g.stopOnce.Do(func() {
		close(g.stopCh)
	})
}

// Incarnation returns the local node's current incarnation number.
func (g *GossipEngine) Incarnation() uint64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.incarnation
}

// ProcessIncomingMessage ingests and evaluates a gossip packet from a peer, returning an ACK response.
func (g *GossipEngine) ProcessIncomingMessage(msg GossipMessage) *GossipMessage {
	atomic.AddUint64(&g.messagesRecv, 1)

	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now().UTC()

	// Update or register the sender as alive
	if msg.SenderID != "" && msg.SenderID != g.localID {
		sender, exists := g.members[msg.SenderID]
		if !exists {
			sender = &GossipMember{
				NodeID:   msg.SenderID,
				NodeName: msg.SenderName,
				Address:  msg.SenderAddr,
			}
			g.members[msg.SenderID] = sender
		}
		if msg.Incarnation >= sender.Incarnation {
			sender.State = GossipStateAlive
			sender.Incarnation = msg.Incarnation
			sender.LastSeen = now
			sender.SuspectSince = time.Time{}
			if msg.SenderAddr != "" {
				sender.Address = msg.SenderAddr
			}
			if msg.SenderName != "" {
				sender.NodeName = msg.SenderName
			}
		}
	}

	// Ingest piggybacked member digests
	for _, digest := range msg.Members {
		g.applyDigestLocked(digest, now)
	}

	// Respond with ACK if requested
	if msg.Type == "ping" || msg.Type == "ping_req" {
		digests := g.collectDigestsLocked()
		ack := &GossipMessage{
			Type:        "ack",
			SenderID:    g.localID,
			SenderName:  g.localName,
			SenderAddr:  g.localAddr,
			Incarnation: g.incarnation,
			Members:     digests,
			Timestamp:   now.Unix(),
		}
		atomic.AddUint64(&g.messagesSent, 1)
		return ack
	}

	return nil
}

func (g *GossipEngine) applyDigestLocked(d GossipMemberDigest, now time.Time) {
	if d.NodeID == "" {
		return
	}

	// Incarnation Refutation Rule: If another node suspects us, refute by incrementing incarnation
	if d.NodeID == g.localID {
		if d.State == GossipStateSuspect && d.Incarnation >= g.incarnation {
			g.incarnation = d.Incarnation + 1
			if self, ok := g.members[g.localID]; ok {
				self.Incarnation = g.incarnation
				self.State = GossipStateAlive
				self.LastSeen = now
				self.SuspectSince = time.Time{}
			}
		}
		return
	}

	m, exists := g.members[d.NodeID]
	if !exists {
		// New peer discovered via gossip infection
		m = &GossipMember{
			NodeID:      d.NodeID,
			NodeName:    d.NodeName,
			Address:     d.Address,
			State:       d.State,
			Incarnation: d.Incarnation,
			LastSeen:    now,
		}
		if d.State == GossipStateSuspect {
			m.SuspectSince = now
		}
		g.members[d.NodeID] = m

		if g.registry != nil && d.Address != "" {
			_ = g.registry.Register(&Node{
				ID:      d.NodeID,
				Name:    d.NodeName,
				Address: d.Address,
				Status:  toNodeStatus(d.State),
				Labels:  map[string]string{"discovered": "gossip-swim"},
			})
		}
		return
	}

	// SWIM update precedence rules:
	// 1. Higher incarnation overrides lower
	if d.Incarnation > m.Incarnation {
		m.Incarnation = d.Incarnation
		m.State = d.State
		m.LastSeen = now
		if d.State == GossipStateSuspect {
			m.SuspectSince = now
		} else {
			m.SuspectSince = time.Time{}
		}
		if d.Address != "" {
			m.Address = d.Address
		}
		if d.NodeName != "" {
			m.NodeName = d.NodeName
		}
		g.notifyRegistryLocked(m)
		return
	}

	// 2. Same incarnation: Dead > Suspect > Alive
	if d.Incarnation == m.Incarnation {
		if d.State == GossipStateDead && m.State != GossipStateDead {
			m.State = GossipStateDead
			g.notifyRegistryLocked(m)
		} else if d.State == GossipStateSuspect && m.State == GossipStateAlive {
			m.State = GossipStateSuspect
			m.SuspectSince = now
			g.notifyRegistryLocked(m)
		}
	}
}

func (g *GossipEngine) notifyRegistryLocked(m *GossipMember) {
	if g.registry == nil {
		return
	}
	g.registry.UpdateNodeStatus(m.NodeID, toNodeStatus(m.State), m.LatencyMs, NodeMetrics{}, nil, "")
}

func toNodeStatus(s GossipState) NodeStatus {
	switch s {
	case GossipStateAlive:
		return NodeStatusOnline
	case GossipStateSuspect:
		return NodeStatusDegraded
	case GossipStateDead:
		return NodeStatusOffline
	default:
		return NodeStatusUnknown
	}
}

func (g *GossipEngine) collectDigestsLocked() []GossipMemberDigest {
	digests := make([]GossipMemberDigest, 0, len(g.members))
	for _, m := range g.members {
		digests = append(digests, GossipMemberDigest{
			NodeID:      m.NodeID,
			NodeName:    m.NodeName,
			Address:     m.Address,
			State:       m.State,
			Incarnation: m.Incarnation,
		})
	}
	return digests
}

func (g *GossipEngine) pingLoop(ctx context.Context) {
	ticker := time.NewTicker(g.cfg.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-g.stopCh:
			return
		case <-ticker.C:
			g.executePingRound(ctx)
		}
	}
}

func (g *GossipEngine) executePingRound(ctx context.Context) {
	g.syncRegistryPeers()

	target := g.pickRandomPeer()
	if target == nil {
		return
	}

	// 1. Direct Ping
	success, latencyMs, ack := g.sendPing(ctx, target.Address, target.NodeID)
	if success {
		g.mu.Lock()
		target.State = GossipStateAlive
		target.LastSeen = time.Now().UTC()
		target.SuspectSince = time.Time{}
		target.LatencyMs = latencyMs
		if ack != nil {
			now := time.Now().UTC()
			for _, d := range ack.Members {
				g.applyDigestLocked(d, now)
			}
		}
		g.notifyRegistryLocked(target)
		g.mu.Unlock()
		return
	}

	// 2. Direct ping failed, attempt Indirect Ping (SWIM ping_req)
	indirectSuccess := g.attemptIndirectPing(ctx, target)
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now().UTC()
	if indirectSuccess {
		target.State = GossipStateAlive
		target.LastSeen = now
		target.SuspectSince = time.Time{}
		g.notifyRegistryLocked(target)
	} else {
		// Mark as Suspect
		if target.State != GossipStateDead {
			target.State = GossipStateSuspect
			target.SuspectSince = now
			g.notifyRegistryLocked(target)
		}
	}
}

func (g *GossipEngine) attemptIndirectPing(ctx context.Context, target *GossipMember) bool {
	helpers := g.pickKRandomHelpers(target.NodeID, g.cfg.KIndirect)
	if len(helpers) == 0 {
		return false
	}

	var wg sync.WaitGroup
	var anySuccess int32

	for _, helper := range helpers {
		h := helper
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := GossipMessage{
				Type:        "ping_req",
				SenderID:    g.localID,
				SenderName:  g.localName,
				SenderAddr:  g.localAddr,
				TargetID:    target.NodeID,
				Incarnation: g.Incarnation(),
				Timestamp:   time.Now().Unix(),
			}
			ok, _, _ := g.dispatchHTTPRequest(ctx, h.Address, req)
			if ok {
				atomic.StoreInt32(&anySuccess, 1)
			}
		}()
	}
	wg.Wait()
	return atomic.LoadInt32(&anySuccess) == 1
}

func (g *GossipEngine) sendPing(ctx context.Context, addr, targetID string) (bool, int64, *GossipMessage) {
	g.mu.RLock()
	digests := g.collectDigestsLocked()
	inc := g.incarnation
	g.mu.RUnlock()

	msg := GossipMessage{
		Type:        "ping",
		SenderID:    g.localID,
		SenderName:  g.localName,
		SenderAddr:  g.localAddr,
		TargetID:    targetID,
		Incarnation: inc,
		Members:     digests,
		Timestamp:   time.Now().Unix(),
	}

	start := time.Now()
	ok, _, ack := g.dispatchHTTPRequest(ctx, addr, msg)
	latencyMs := time.Since(start).Milliseconds()
	return ok, latencyMs, ack
}

func (g *GossipEngine) dispatchHTTPRequest(ctx context.Context, addr string, msg GossipMessage) (bool, int64, *GossipMessage) {
	if addr == "" {
		return false, 0, nil
	}

	url := fmt.Sprintf("%s/api/mesh/gossip", addr)
	payload, err := json.Marshal(msg)
	if err != nil {
		return false, 0, nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, g.cfg.PingTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return false, 0, nil
	}
	req.Header.Set("Content-Type", "application/json")
	if g.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+g.cfg.AuthToken)
	}

	atomic.AddUint64(&g.messagesSent, 1)
	start := time.Now()

	resp, err := g.cfg.HTTPClient.Do(req)
	if err != nil {
		return false, 0, nil
	}
	defer resp.Body.Close()

	latencyMs := time.Since(start).Milliseconds()
	if resp.StatusCode != http.StatusOK {
		return false, latencyMs, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxGossipPayloadBytes))
	if err != nil {
		return true, latencyMs, nil
	}

	var ack GossipMessage
	if err := json.Unmarshal(body, &ack); err != nil {
		return true, latencyMs, nil
	}

	return true, latencyMs, &ack
}

func (g *GossipEngine) suspectWatchdog(ctx context.Context) {
	ticker := time.NewTicker(g.cfg.SuspectTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-g.stopCh:
			return
		case <-ticker.C:
			g.checkSuspects()
		}
	}
}

func (g *GossipEngine) checkSuspects() {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now().UTC()
	limit := g.cfg.SuspectTimeout

	for _, m := range g.members {
		if m.NodeID == g.localID {
			continue
		}
		if m.State == GossipStateSuspect && !m.SuspectSince.IsZero() && now.Sub(m.SuspectSince) > limit {
			m.State = GossipStateDead
			atomic.AddUint64(&g.suspectTimeouts, 1)
			g.notifyRegistryLocked(m)
		}
	}
}

func (g *GossipEngine) syncRegistryPeers() {
	if g.registry == nil {
		return
	}
	nodes := g.registry.List()
	g.mu.Lock()
	defer g.mu.Unlock()

	for _, n := range nodes {
		if n.ID == g.localID {
			continue
		}
		if _, exists := g.members[n.ID]; !exists {
			g.members[n.ID] = &GossipMember{
				NodeID:      n.ID,
				NodeName:    n.Name,
				Address:     n.Address,
				State:       GossipStateAlive,
				Incarnation: 0,
				LastSeen:    time.Now().UTC(),
			}
		}
	}
}

func (g *GossipEngine) pickRandomPeer() *GossipMember {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var candidates []*GossipMember
	for _, m := range g.members {
		if m.NodeID == g.localID {
			continue
		}
		// Allow picking alive and suspect nodes for verification
		candidates = append(candidates, m)
	}

	if len(candidates) == 0 {
		return nil
	}

	idxBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	if err != nil {
		return candidates[0]
	}
	return candidates[idxBig.Int64()]
}

func (g *GossipEngine) pickKRandomHelpers(targetID string, k int) []*GossipMember {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var candidates []*GossipMember
	for _, m := range g.members {
		if m.NodeID == g.localID || m.NodeID == targetID || m.State != GossipStateAlive {
			continue
		}
		candidates = append(candidates, m)
	}

	if len(candidates) <= k {
		return candidates
	}

	// Shuffle slice and select first k
	for i := len(candidates) - 1; i > 0; i-- {
		jBig, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := int(jBig.Int64())
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}
	return candidates[:k]
}

// Members returns an immutable snapshot of all known cluster members.
func (g *GossipEngine) Members() []GossipMember {
	g.mu.RLock()
	defer g.mu.RUnlock()

	list := make([]GossipMember, 0, len(g.members))
	for _, m := range g.members {
		list = append(list, *m)
	}
	return list
}

// Summary returns high-level KPI metrics about the SWIM cluster state.
func (g *GossipEngine) Summary() GossipSummary {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var alive, suspect, dead int
	for _, m := range g.members {
		switch m.State {
		case GossipStateAlive:
			alive++
		case GossipStateSuspect:
			suspect++
		case GossipStateDead:
			dead++
		}
	}

	return GossipSummary{
		LocalID:         g.localID,
		LocalName:       g.localName,
		Incarnation:     g.incarnation,
		TotalMembers:    len(g.members),
		AliveMembers:    alive,
		SuspectMembers:  suspect,
		DeadMembers:     dead,
		MessagesSent:    atomic.LoadUint64(&g.messagesSent),
		MessagesRecv:    atomic.LoadUint64(&g.messagesRecv),
		SuspectTimeouts: atomic.LoadUint64(&g.suspectTimeouts),
	}
}

// AddMember explicitly adds a member to the SWIM membership table.
func (g *GossipEngine) AddMember(m *GossipMember) error {
	if m == nil || m.NodeID == "" {
		return errors.New("cannot add invalid gossip member")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.members[m.NodeID] = m
	return nil
}
