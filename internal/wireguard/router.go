package wireguard

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type routeItem struct {
	network *net.IPNet
	peerID  string
	metric  int
}

// Router maintains the cryptokey routing table and dynamic NAT endpoint roaming directory.
type Router struct {
	mu            sync.RWMutex
	routes        []routeItem
	peerEndpoints map[string]*net.UDPAddr // peerID -> active remote UDP address
	peerAllowed   map[string][]*net.IPNet // peerID -> allowed IP ranges
}

// NewRouter constructs a fresh routing table instance.
func NewRouter() *Router {
	return &Router{
		routes:        make([]routeItem, 0),
		peerEndpoints: make(map[string]*net.UDPAddr),
		peerAllowed:   make(map[string][]*net.IPNet),
	}
}

// RegisterPeerRoutes associates allowed IP prefixes with a peer for cryptokey routing.
func (r *Router) RegisterPeerRoutes(peerID string, allowedIPs []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	parsedNets := make([]*net.IPNet, 0, len(allowedIPs))

	for _, raw := range allowedIPs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// If single IP without CIDR mask, default to /32
		if !strings.Contains(raw, "/") {
			raw = raw + "/32"
		}

		_, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			return fmt.Errorf("invalid allowed IP %q for peer %s: %w", raw, peerID, err)
		}
		parsedNets = append(parsedNets, ipNet)
	}

	// Purge any existing routes for this peer
	r.removePeerRoutesLocked(peerID)

	// Insert new routes
	for _, ipNet := range parsedNets {
		ones, _ := ipNet.Mask.Size()
		metric := 128 - ones // More specific prefix has lower metric (higher priority)
		r.routes = append(r.routes, routeItem{
			network: ipNet,
			peerID:  peerID,
			metric:  metric,
		})
	}

	r.peerAllowed[peerID] = parsedNets
	return nil
}

func (r *Router) removePeerRoutesLocked(peerID string) {
	filtered := make([]routeItem, 0, len(r.routes))
	for _, item := range r.routes {
		if item.peerID != peerID {
			filtered = append(filtered, item)
		}
	}
	r.routes = filtered
	delete(r.peerAllowed, peerID)
}

// RemovePeerRoutes clears all routing entries and dynamic endpoints associated with a peer.
func (r *Router) RemovePeerRoutes(peerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.removePeerRoutesLocked(peerID)
	delete(r.peerEndpoints, peerID)
}

// LookupPeer determines the target peer ID responsible for handling traffic to dstIP.
func (r *Router) LookupPeer(dstIP net.IP) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var bestPeer string
	bestMetric := 999999

	for _, item := range r.routes {
		if item.network.Contains(dstIP) {
			if item.metric < bestMetric {
				bestMetric = item.metric
				bestPeer = item.peerID
			}
		}
	}

	if bestPeer != "" {
		return bestPeer, true
	}
	return "", false
}

// ValidateIngress enforces zero-trust cryptokey routing by verifying packet source IP against peer AllowedIPs.
func (r *Router) ValidateIngress(peerID string, srcIP net.IP) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	allowedList, found := r.peerAllowed[peerID]
	if !found {
		return false
	}

	for _, ipNet := range allowedList {
		if ipNet.Contains(srcIP) {
			return true
		}
	}

	return false
}

// UpdatePeerEndpoint dynamically records the external UDP address observed for a peer (NAT roaming).
func (r *Router) UpdatePeerEndpoint(peerID string, addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.peerEndpoints[peerID] = addr
}

// GetPeerEndpoint retrieves the current known remote UDP address for a peer.
func (r *Router) GetPeerEndpoint(peerID string) *net.UDPAddr {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.peerEndpoints[peerID]
}

// SetInitialEndpoint parses and configures a static initial endpoint for a peer.
func (r *Router) SetInitialEndpoint(peerID string, endpointStr string) error {
	endpointStr = strings.TrimSpace(endpointStr)
	if endpointStr == "" {
		return nil
	}

	addr, err := net.ResolveUDPAddr("udp", endpointStr)
	if err != nil {
		return fmt.Errorf("failed to resolve peer endpoint %q: %w", endpointStr, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.peerEndpoints[peerID] = addr
	return nil
}

// ListRoutes exports all active routing entries as structured records.
func (r *Router) ListRoutes() []RouteEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now().UTC()
	entries := make([]RouteEntry, 0, len(r.routes))

	for _, item := range r.routes {
		var epStr string
		if ep, found := r.peerEndpoints[item.peerID]; found && ep != nil {
			epStr = ep.String()
		}

		entries = append(entries, RouteEntry{
			Destination: item.network.String(),
			PeerID:      item.peerID,
			ViaEndpoint: epStr,
			Metric:      item.metric,
			UpdatedAt:   now,
		})
	}

	return entries
}

// RoutesCount returns the total number of registered prefix routes.
func (r *Router) RoutesCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.routes)
}

// ParsePacketHeaders parses minimal IPv4 header to extract source and destination IP addresses.
func ParsePacketHeaders(packet []byte) (srcIP net.IP, dstIP net.IP, err error) {
	if len(packet) < 20 {
		return nil, nil, errors.New("packet shorter than minimum IPv4 header (20 bytes)")
	}

	version := packet[0] >> 4
	if version != 4 {
		return nil, nil, fmt.Errorf("unsupported IP version %d (expected 4)", version)
	}

	src := net.IP(packet[12:16])
	dst := net.IP(packet[16:20])

	return src, dst, nil
}
