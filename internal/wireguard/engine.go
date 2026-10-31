package wireguard

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/audit"
)

// Engine orchestrates the userspace WireGuard mesh overlay, cryptographic peering, and packet routing.
type Engine struct {
	mu              sync.RWMutex
	config          WireGuardConfig
	keyPair         *KeyPair
	pool            *IPPool
	router          *Router
	peers           map[string]*PeerConfig
	peerCiphers     map[string]*PacketCipher
	txSeq           map[string]*uint64
	auditLogger     *audit.Logger
	alertDispatcher *alert.Dispatcher
	udpConn         *net.UDPConn
	running         bool
	stopChan        chan struct{}
	totalRx         uint64
	totalTx         uint64
	lastKeyRotation time.Time
}

// NewEngine constructs and initializes a WireGuard mesh engine with dedicated IP pool and router.
func NewEngine(cfg WireGuardConfig, auditLogger *audit.Logger, alertDispatcher *alert.Dispatcher) (*Engine, error) {
	if cfg.InterfaceName == "" {
		cfg.InterfaceName = "wg-radar0"
	}
	if cfg.ListenPort <= 0 {
		cfg.ListenPort = 51820
	}
	if cfg.VirtualCIDR == "" {
		cfg.VirtualCIDR = "10.42.0.0/24"
	}
	if cfg.KeepaliveInterval <= 0 {
		cfg.KeepaliveInterval = 25
	}
	if cfg.MaxPeers <= 0 {
		cfg.MaxPeers = 256
	}

	var keyPair *KeyPair
	var err error

	if cfg.PrivateKey != "" && cfg.PublicKey != "" {
		if err := ValidateKey(cfg.PrivateKey); err != nil {
			return nil, fmt.Errorf("invalid configured private key: %w", err)
		}
		if err := ValidateKey(cfg.PublicKey); err != nil {
			return nil, fmt.Errorf("invalid configured public key: %w", err)
		}
		keyPair = &KeyPair{
			PrivateKeyBase64: cfg.PrivateKey,
			PublicKeyBase64:  cfg.PublicKey,
			CreatedAt:        time.Now().UTC(),
		}
	} else {
		keyPair, err = GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate host WireGuard keypair: %w", err)
		}
		cfg.PrivateKey = keyPair.PrivateKeyBase64
		cfg.PublicKey = keyPair.PublicKeyBase64
	}

	pool, err := NewIPPool(cfg.VirtualCIDR, cfg.VirtualIP, 24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize overlay IP pool: %w", err)
	}
	cfg.VirtualIP = pool.GatewayIP()

	router := NewRouter()

	return &Engine{
		config:          cfg,
		keyPair:         keyPair,
		pool:            pool,
		router:          router,
		peers:           make(map[string]*PeerConfig),
		peerCiphers:     make(map[string]*PacketCipher),
		txSeq:           make(map[string]*uint64),
		auditLogger:     auditLogger,
		alertDispatcher: alertDispatcher,
		stopChan:        make(chan struct{}),
		lastKeyRotation: time.Now().UTC(),
	}, nil
}

// AddPeer registers or updates a peer in the WireGuard mesh, allocating an overlay IP lease.
func (e *Engine) AddPeer(peer PeerConfig) (*PeerConfig, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := ValidatePeerID(peer.ID); err != nil {
		return nil, err
	}
	if err := ValidateKey(peer.PublicKey); err != nil {
		return nil, fmt.Errorf("peer public key invalid: %w", err)
	}
	if peer.PresharedKey != "" {
		if err := ValidateKey(peer.PresharedKey); err != nil {
			return nil, fmt.Errorf("peer preshared key invalid: %w", err)
		}
	}
	if len(e.peers) >= e.config.MaxPeers {
		return nil, fmt.Errorf("maximum allowed mesh peers reached (%d)", e.config.MaxPeers)
	}

	// Dynamic IP allocation if not manually assigned
	leasedIP, err := e.pool.Allocate(peer.ID, peer.LeasedIP)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate overlay IP for peer %s: %w", peer.ID, err)
	}
	peer.LeasedIP = leasedIP

	// Ensure leased IP is in AllowedIPs
	hasLeased := false
	for _, a := range peer.AllowedIPs {
		if a == leasedIP || a == leasedIP+"/32" {
			hasLeased = true
			break
		}
	}
	if !hasLeased {
		peer.AllowedIPs = append(peer.AllowedIPs, leasedIP+"/32")
	}

	// Register routes in router
	if err := e.router.RegisterPeerRoutes(peer.ID, peer.AllowedIPs); err != nil {
		return nil, fmt.Errorf("failed to configure routes for peer %s: %w", peer.ID, err)
	}

	if peer.Endpoint != "" {
		_ = e.router.SetInitialEndpoint(peer.ID, peer.Endpoint)
	}

	if peer.PersistentKeepalive <= 0 {
		peer.PersistentKeepalive = e.config.KeepaliveInterval
	}
	peer.Status = PeerStatusHandshakePending

	// Initialize cipher
	sharedSecret, err := DeriveSharedSecret(e.keyPair.PrivateKeyBase64, peer.PublicKey)
	if err == nil {
		sessionLabel := canonicalSessionLabel(e.keyPair.PublicKeyBase64, peer.PublicKey)
		tunnelKey, err := DeriveTunnelKey(sharedSecret, peer.PresharedKey, sessionLabel)
		if err == nil {
			if existingCipher, ok := e.peerCiphers[peer.ID]; ok {
				existingCipher.Close()
			}
			pc, err := NewPacketCipher(tunnelKey)
			if err == nil {
				e.peerCiphers[peer.ID] = pc
				peer.Status = PeerStatusConnected
				peer.LastHandshake = time.Now().UTC()
			}
		}
	}

	var seq uint64
	e.txSeq[peer.ID] = &seq
	saved := peer
	e.peers[peer.ID] = &saved

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action: "wireguard_peer_add",
			Target: peer.ID,
			Details: map[string]any{
				"name":        peer.Name,
				"public_key":  MaskKey(peer.PublicKey),
				"leased_ip":   peer.LeasedIP,
				"allowed_ips": peer.AllowedIPs,
				"endpoint":    peer.Endpoint,
			},
		})
	}

	return &saved, nil
}

// RemovePeer evicts a peer from the WireGuard mesh and reclaims its overlay IP lease.
func (e *Engine) RemovePeer(peerID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	peer, found := e.peers[peerID]
	if !found {
		return false
	}

	if pc, ok := e.peerCiphers[peerID]; ok {
		pc.Close()
		delete(e.peerCiphers, peerID)
	}
	delete(e.txSeq, peerID)
	delete(e.peers, peerID)

	e.router.RemovePeerRoutes(peerID)
	e.pool.Release(peerID)

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action: "wireguard_peer_remove",
			Target: peerID,
			Details: map[string]any{
				"leased_ip": peer.LeasedIP,
			},
		})
	}

	return true
}

// GetPeer looks up an active mesh peer configuration.
func (e *Engine) GetPeer(peerID string) (PeerConfig, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	peer, found := e.peers[peerID]
	if !found {
		return PeerConfig{}, false
	}
	copy := *peer
	copy.PresharedKey = MaskKey(copy.PresharedKey)
	return copy, true
}

// ListPeers retrieves all registered peers with masked sensitive credentials.
func (e *Engine) ListPeers() []PeerConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list := make([]PeerConfig, 0, len(e.peers))
	for _, p := range e.peers {
		copy := *p
		copy.PresharedKey = MaskKey(copy.PresharedKey)
		list = append(list, copy)
	}
	return list
}

func canonicalSessionLabel(pubA, pubB string) string {
	if pubA < pubB {
		return pubA + ":" + pubB
	}
	return pubB + ":" + pubA
}

// InitiateHandshake computes fresh cryptographic session keys and re-establishes a peer tunnel.
func (e *Engine) InitiateHandshake(peerID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	peer, found := e.peers[peerID]
	if !found {
		return fmt.Errorf("peer %q not found", peerID)
	}

	sharedSecret, err := DeriveSharedSecret(e.keyPair.PrivateKeyBase64, peer.PublicKey)
	if err != nil {
		return fmt.Errorf("handshake ECDH computation failed: %w", err)
	}

	sessionLabel := canonicalSessionLabel(e.keyPair.PublicKeyBase64, peer.PublicKey)
	tunnelKey, err := DeriveTunnelKey(sharedSecret, peer.PresharedKey, sessionLabel)
	if err != nil {
		return fmt.Errorf("tunnel key derivation failed: %w", err)
	}

	if pc, ok := e.peerCiphers[peerID]; ok {
		pc.Close()
	}

	pc, err := NewPacketCipher(tunnelKey)
	if err != nil {
		return fmt.Errorf("failed to initialize packet cipher: %w", err)
	}

	e.peerCiphers[peerID] = pc
	peer.Status = PeerStatusConnected
	peer.LastHandshake = time.Now().UTC()

	if e.auditLogger != nil {
		e.auditLogger.Log(audit.AuditEvent{
			Action: "wireguard_handshake_success",
			Target: peerID,
			Details: map[string]any{
				"public_key": MaskKey(peer.PublicKey),
				"timestamp":  peer.LastHandshake,
			},
		})
	}

	return nil
}

// SendPacket encrypts a packet and forwards it to the peer responsible for dstIP via cryptokey routing.
func (e *Engine) SendPacket(dstIP net.IP, plaintext []byte) ([]byte, string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	peerID, found := e.router.LookupPeer(dstIP)
	if !found {
		return nil, "", fmt.Errorf("no route to overlay destination IP %s", dstIP.String())
	}

	cipher, hasCipher := e.peerCiphers[peerID]
	if !hasCipher {
		return nil, peerID, fmt.Errorf("no active cryptographic session for peer %s", peerID)
	}

	seqPtr := e.txSeq[peerID]
	if seqPtr == nil {
		var s uint64
		seqPtr = &s
		e.txSeq[peerID] = seqPtr
	}
	seq := atomic.AddUint64(seqPtr, 1)

	ciphertext, err := cipher.EncryptPacket(seq, plaintext)
	if err != nil {
		return nil, peerID, fmt.Errorf("packet encryption failed: %w", err)
	}

	peer := e.peers[peerID]
	peer.TxBytes += uint64(len(ciphertext))
	atomic.AddUint64(&e.totalTx, uint64(len(ciphertext)))

	return ciphertext, peerID, nil
}

// ReceivePacket authenticates and decrypts an incoming packet, verifying zero-trust AllowedIPs rules.
func (e *Engine) ReceivePacket(peerID string, encryptedPacket []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	peer, found := e.peers[peerID]
	if !found {
		return nil, fmt.Errorf("unknown peer %q", peerID)
	}

	cipher, hasCipher := e.peerCiphers[peerID]
	if !hasCipher {
		return nil, fmt.Errorf("no active cipher session for peer %s", peerID)
	}

	_, plaintext, err := cipher.DecryptPacket(encryptedPacket)
	if err != nil {
		return nil, fmt.Errorf("packet decryption/verification failed: %w", err)
	}

	// Validate ingress source IP matches peer's AllowedIPs
	srcIP, _, err := ParsePacketHeaders(plaintext)
	if err == nil {
		if !e.router.ValidateIngress(peerID, srcIP) {
			return nil, fmt.Errorf("zero-trust violation: source IP %s not in peer %s AllowedIPs", srcIP.String(), peerID)
		}
	}

	peer.RxBytes += uint64(len(encryptedPacket))
	peer.Status = PeerStatusConnected
	atomic.AddUint64(&e.totalRx, uint64(len(encryptedPacket)))

	return plaintext, nil
}

// Router returns the underlying mesh routing engine.
func (e *Engine) Router() *Router {
	return e.router
}

// Pool returns the overlay IP pool allocator.
func (e *Engine) Pool() *IPPool {
	return e.pool
}

// Status returns a telemetry snapshot of the WireGuard mesh subsystem.
func (e *Engine) Status() WireGuardStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	activeCount := 0
	for _, p := range e.peers {
		if p.Status == PeerStatusConnected {
			activeCount++
		}
	}

	return WireGuardStatus{
		Enabled:           e.config.Enabled,
		InterfaceName:     e.config.InterfaceName,
		ListenPort:        e.config.ListenPort,
		PublicKey:         e.keyPair.PublicKeyBase64,
		VirtualIP:         e.config.VirtualIP,
		VirtualCIDR:       e.config.VirtualCIDR,
		ActivePeers:       activeCount,
		TotalPeers:        len(e.peers),
		TotalRxBytes:      atomic.LoadUint64(&e.totalRx),
		TotalTxBytes:      atomic.LoadUint64(&e.totalTx),
		ActiveLeases:      e.pool.ActiveCount(),
		RoutingRulesCount: e.router.RoutesCount(),
		LastKeyRotation:   e.lastKeyRotation,
	}
}

// Config returns the active WireGuard configuration with the private key masked.
func (e *Engine) Config() WireGuardConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()

	copy := e.config
	copy.PrivateKey = MaskKey(copy.PrivateKey)
	return copy
}

// Start begins background maintenance routines (lease reclaiming, NAT keepalive pings).
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = true
	e.mu.Unlock()

	go e.maintenanceLoop(ctx)
	return nil
}

// Stop gracefully shuts down the WireGuard engine and cleans up active sessions.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return
	}
	e.running = false
	close(e.stopChan)

	for _, pc := range e.peerCiphers {
		pc.Close()
	}
}

func (e *Engine) maintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopChan:
			return
		case <-ticker.C:
			// Reclaim expired overlay IP leases
			reclaimed := e.pool.ReclaimExpired()
			if reclaimed > 0 && e.auditLogger != nil {
				e.auditLogger.Log(audit.AuditEvent{
					Action:  "wireguard_leases_reclaimed",
					Target:  "ippool",
					Details: map[string]any{"count": reclaimed},
				})
			}
		}
	}
}
