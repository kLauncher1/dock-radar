package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultDiscoveryPort is the default UDP port for LAN auto-discovery beacons.
	DefaultDiscoveryPort = 9085
	// DefaultBeaconInterval is the frequency of UDP broadcast beacon announcements.
	DefaultBeaconInterval = 10 * time.Second
	// DefaultPeerTTL defines how long a discovered peer remains valid before expiration.
	DefaultPeerTTL = 45 * time.Second
	// DefaultClusterKey is the default cluster isolation key.
	DefaultClusterKey = "dock-radar-cluster"
	// MaxDiscoveryPacketSize bounds incoming UDP datagram size to prevent memory attacks.
	MaxDiscoveryPacketSize = 1024
)

// DiscoveredPeer captures metadata about a peer node detected on the local network.
type DiscoveredPeer struct {
	NodeID       string    `json:"node_id"`
	NodeName     string    `json:"node_name"`
	Address      string    `json:"address"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	BeaconsCount uint64    `json:"beacons_count"`
}

// BeaconPacket represents the serialized datagram payload sent over UDP broadcast.
type BeaconPacket struct {
	Type       string `json:"type"`
	Version    int    `json:"version"`
	NodeID     string `json:"node_id"`
	NodeName   string `json:"node_name"`
	Address    string `json:"address"`
	ClusterKey string `json:"cluster_key"`
	Timestamp  int64  `json:"timestamp"`
}

// DiscoveryConfig defines tunable parameters for the UDP broadcast auto-discovery engine.
type DiscoveryConfig struct {
	Enabled        bool          `json:"enabled"`
	Port           int           `json:"port"`
	BeaconInterval time.Duration `json:"beacon_interval"`
	PeerTTL        time.Duration `json:"peer_ttl"`
	ClusterKey     string        `json:"cluster_key"`
	NodeID         string        `json:"node_id"`
	NodeName       string        `json:"node_name"`
	Address        string        `json:"address"`
}

// DiscoveryStatus encapsulates runtime telemetry about the auto-discovery service.
type DiscoveryStatus struct {
	Enabled         bool             `json:"enabled"`
	Listening       bool             `json:"listening"`
	Port            int              `json:"port"`
	ClusterKey      string           `json:"cluster_key"`
	BeaconsSent     uint64           `json:"beacons_sent"`
	BeaconsReceived uint64           `json:"beacons_received"`
	PeersCount      int              `json:"peers_count"`
	Peers           []DiscoveredPeer `json:"peers"`
	LastError       string           `json:"last_error,omitempty"`
}

// DiscoveryEngine orchestrates UDP broadcast announcements and LAN peer discovery.
type DiscoveryEngine struct {
	mu              sync.RWMutex
	cfg             DiscoveryConfig
	registry        *Registry
	peers           map[string]*DiscoveredPeer
	conn            *net.UDPConn
	stopCh          chan struct{}
	stopOnce        sync.Once
	listening       bool
	lastError       string
	beaconsSent     uint64
	beaconsReceived uint64
}

// NewDiscoveryEngine initializes the UDP peer discovery engine with safe defaults.
func NewDiscoveryEngine(cfg DiscoveryConfig, registry *Registry) *DiscoveryEngine {
	if cfg.Port <= 0 {
		cfg.Port = DefaultDiscoveryPort
	}
	if cfg.BeaconInterval <= 0 {
		cfg.BeaconInterval = DefaultBeaconInterval
	}
	if cfg.PeerTTL <= 0 {
		cfg.PeerTTL = DefaultPeerTTL
	}
	if cfg.ClusterKey == "" {
		cfg.ClusterKey = DefaultClusterKey
	}

	return &DiscoveryEngine{
		cfg:      cfg,
		registry: registry,
		peers:    make(map[string]*DiscoveredPeer),
		stopCh:   make(chan struct{}),
	}
}

// Start begins listening for UDP beacons and schedules periodic broadcast announcements.
func (e *DiscoveryEngine) Start(ctx context.Context) error {
	if !e.cfg.Enabled {
		return nil
	}

	listenAddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: e.cfg.Port,
	}

	conn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		e.mu.Lock()
		e.lastError = err.Error()
		e.mu.Unlock()
		return fmt.Errorf("failed to bind UDP discovery port %d: %w", e.cfg.Port, err)
	}

	e.mu.Lock()
	e.conn = conn
	e.listening = true
	e.lastError = ""
	e.mu.Unlock()

	go e.listenLoop(conn)
	go e.beaconLoop(ctx)
	go e.sweepLoop(ctx)

	// Send an immediate announcement beacon on start
	_ = e.BroadcastBeacon()
	return nil
}

// Stop cleanly terminates UDP sockets and background discovery routines.
func (e *DiscoveryEngine) Stop() {
	e.stopOnce.Do(func() {
		close(e.stopCh)
		e.mu.Lock()
		if e.conn != nil {
			_ = e.conn.Close()
		}
		e.listening = false
		e.mu.Unlock()
	})
}

// BroadcastBeacon broadcasts a single announcement packet across LAN broadcast interfaces.
func (e *DiscoveryEngine) BroadcastBeacon() error {
	e.mu.RLock()
	nodeID := e.cfg.NodeID
	nodeName := e.cfg.NodeName
	address := e.cfg.Address
	clusterKey := e.cfg.ClusterKey
	port := e.cfg.Port
	e.mu.RUnlock()

	if nodeID == "" || address == "" {
		return errors.New("cannot broadcast beacon: node ID or address is not configured")
	}

	packet := BeaconPacket{
		Type:       "beacon",
		Version:    1,
		NodeID:     nodeID,
		NodeName:   nodeName,
		Address:    address,
		ClusterKey: clusterKey,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := json.Marshal(packet)
	if err != nil {
		return fmt.Errorf("failed to encode beacon packet: %w", err)
	}

	broadcastAddrs := getBroadcastAddresses(port)
	if len(broadcastAddrs) == 0 {
		broadcastAddrs = []net.UDPAddr{{IP: net.IPv4bcast, Port: port}}
	}

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return fmt.Errorf("failed to open UDP broadcast sender: %w", err)
	}
	defer sender.Close()

	var sent bool
	for _, target := range broadcastAddrs {
		t := target
		_, err := sender.WriteTo(payload, &t)
		if err == nil {
			sent = true
		}
	}

	if sent {
		atomic.AddUint64(&e.beaconsSent, 1)
		return nil
	}
	return errors.New("failed to transmit beacon across broadcast interfaces")
}

func (e *DiscoveryEngine) listenLoop(conn *net.UDPConn) {
	buf := make([]byte, MaxDiscoveryPacketSize)
	for {
		select {
		case <-e.stopCh:
			return
		default:
		}

		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-e.stopCh:
				return
			default:
				continue
			}
		}

		if n <= 0 || n > MaxDiscoveryPacketSize {
			continue
		}

		var pkt BeaconPacket
		if err := json.Unmarshal(buf[:n], &pkt); err != nil {
			continue
		}

		e.handleIncomingBeacon(&pkt, remoteAddr)
	}
}

func (e *DiscoveryEngine) handleIncomingBeacon(pkt *BeaconPacket, remoteAddr *net.UDPAddr) {
	if pkt == nil || pkt.Type != "beacon" {
		return
	}

	e.mu.RLock()
	localID := e.cfg.NodeID
	clusterKey := e.cfg.ClusterKey
	e.mu.RUnlock()

	// Ignore packets originating from this node itself
	if pkt.NodeID == localID || pkt.NodeID == "" {
		return
	}

	// Filter out beacons belonging to different cluster keys
	if pkt.ClusterKey != clusterKey {
		return
	}

	// Validate node ID and address format strictly
	if err := ValidateNodeID(pkt.NodeID); err != nil {
		return
	}
	if err := ValidateNodeAddress(pkt.Address); err != nil {
		return
	}

	atomic.AddUint64(&e.beaconsReceived, 1)

	now := time.Now().UTC()
	e.mu.Lock()
	peer, exists := e.peers[pkt.NodeID]
	if !exists {
		peer = &DiscoveredPeer{
			NodeID:    pkt.NodeID,
			NodeName:  pkt.NodeName,
			Address:   pkt.Address,
			FirstSeen: now,
		}
		e.peers[pkt.NodeID] = peer
	}
	peer.LastSeen = now
	peer.BeaconsCount++
	peer.Address = pkt.Address
	if pkt.NodeName != "" {
		peer.NodeName = pkt.NodeName
	}
	e.mu.Unlock()

	// Automatically register peer with main mesh Registry if absent
	if e.registry != nil {
		if _, exists := e.registry.Get(pkt.NodeID); !exists {
			_ = e.registry.Register(&Node{
				ID:      pkt.NodeID,
				Name:    pkt.NodeName,
				Address: pkt.Address,
				Status:  NodeStatusUnknown,
				Labels:  map[string]string{"discovered": "lan-udp"},
			})
		}
	}
}

func (e *DiscoveryEngine) beaconLoop(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.BeaconInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case <-ticker.C:
			_ = e.BroadcastBeacon()
		}
	}
}

func (e *DiscoveryEngine) sweepLoop(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.PeerTTL / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.sweepExpiredPeers()
		}
	}
}

func (e *DiscoveryEngine) sweepExpiredPeers() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now().UTC()
	ttl := e.cfg.PeerTTL

	for id, peer := range e.peers {
		if now.Sub(peer.LastSeen) > ttl {
			delete(e.peers, id)
		}
	}
}

// DiscoveredPeers returns an immutable snapshot list of currently tracked LAN peers.
func (e *DiscoveryEngine) DiscoveredPeers() []DiscoveredPeer {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list := make([]DiscoveredPeer, 0, len(e.peers))
	for _, p := range e.peers {
		list = append(list, *p)
	}
	return list
}

// Status returns a high-level telemetry report of the discovery subsystem.
func (e *DiscoveryEngine) Status() DiscoveryStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	peers := make([]DiscoveredPeer, 0, len(e.peers))
	for _, p := range e.peers {
		peers = append(peers, *p)
	}

	return DiscoveryStatus{
		Enabled:         e.cfg.Enabled,
		Listening:       e.listening,
		Port:            e.cfg.Port,
		ClusterKey:      e.cfg.ClusterKey,
		BeaconsSent:     atomic.LoadUint64(&e.beaconsSent),
		BeaconsReceived: atomic.LoadUint64(&e.beaconsReceived),
		PeersCount:      len(peers),
		Peers:           peers,
		LastError:       e.lastError,
	}
}

// BeaconsSent returns the total number of broadcast beacons dispatched.
func (e *DiscoveryEngine) BeaconsSent() uint64 {
	return atomic.LoadUint64(&e.beaconsSent)
}

// BeaconsReceived returns the total number of valid broadcast beacons processed.
func (e *DiscoveryEngine) BeaconsReceived() uint64 {
	return atomic.LoadUint64(&e.beaconsReceived)
}

func getBroadcastAddresses(port int) []net.UDPAddr {
	var addrs []net.UDPAddr
	addrs = append(addrs, net.UDPAddr{IP: net.IPv4bcast, Port: port})

	ifaces, err := net.Interfaces()
	if err != nil {
		return addrs
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		unicastAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range unicastAddrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil || ipNet.IP.IsLoopback() {
				continue
			}
			ip4 := ipNet.IP.To4()
			mask := ipNet.Mask
			if len(mask) == 4 {
				bcast := net.IPv4(
					ip4[0]|^mask[0],
					ip4[1]|^mask[1],
					ip4[2]|^mask[2],
					ip4[3]|^mask[3],
				)
				addrs = append(addrs, net.UDPAddr{IP: bcast, Port: port})
			}
		}
	}
	return addrs
}
