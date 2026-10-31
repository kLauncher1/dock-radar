package wireguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// IPPool manages dynamic IP address leasing and allocation for WireGuard mesh overlay peers.
type IPPool struct {
	mu        sync.RWMutex
	subnet    *net.IPNet
	gatewayIP net.IP
	leaseTTL  time.Duration
	leases    map[string]*IPLease // peerID -> lease
	ipToPeer  map[string]string   // ip string -> peerID
	startIP   uint32
	endIP     uint32
}

// NewIPPool initializes an overlay subnet address allocator.
func NewIPPool(cidr string, gatewayIPStr string, leaseTTL time.Duration) (*IPPool, error) {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("invalid overlay CIDR %q: %w", cidr, err)
	}

	ipv4 := ipNet.IP.To4()
	if ipv4 == nil {
		return nil, errors.New("only IPv4 overlay subnets are currently supported")
	}

	mask := binary.BigEndian.Uint32(ipNet.Mask)
	netUint := binary.BigEndian.Uint32(ipv4) & mask
	bcastUint := netUint | ^mask

	var gw net.IP
	if gatewayIPStr != "" {
		gw = net.ParseIP(strings.TrimSpace(gatewayIPStr)).To4()
		if gw == nil || !ipNet.Contains(gw) {
			return nil, fmt.Errorf("gateway IP %q outside overlay subnet %s", gatewayIPStr, cidr)
		}
	} else {
		// Default to first usable address
		gwUint := netUint + 1
		gw = make(net.IP, 4)
		binary.BigEndian.PutUint32(gw, gwUint)
	}

	if leaseTTL <= 0 {
		leaseTTL = 24 * time.Hour
	}

	// Usable range: net+1 to bcast-1
	start := netUint + 1
	end := bcastUint - 1

	pool := &IPPool{
		subnet:    ipNet,
		gatewayIP: gw,
		leaseTTL:  leaseTTL,
		leases:    make(map[string]*IPLease),
		ipToPeer:  make(map[string]string),
		startIP:   start,
		endIP:     end,
	}

	// Reserve gateway IP so it won't be leased to peers
	pool.ipToPeer[gw.String()] = "gateway"

	return pool, nil
}

// Subnet returns the overlay network specification.
func (p *IPPool) Subnet() *net.IPNet {
	return p.subnet
}

// GatewayIP returns the local node's overlay virtual IP.
func (p *IPPool) GatewayIP() string {
	return p.gatewayIP.String()
}

// Allocate assigns a dynamic or requested static overlay IP to a peer.
func (p *IPPool) Allocate(peerID string, preferredIP string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now().UTC()

	// If peer already holds an active lease, renew and return it
	if existing, found := p.leases[peerID]; found && existing.Active {
		if preferredIP == "" || existing.IP == preferredIP {
			existing.ExpiresAt = now.Add(p.leaseTTL)
			return existing.IP, nil
		}
		// Peer requests a different IP: release old one first
		delete(p.ipToPeer, existing.IP)
	}

	// Case 1: Preferred specific IP requested
	if preferredIP != "" {
		reqIP := net.ParseIP(strings.TrimSpace(preferredIP)).To4()
		if reqIP == nil || !p.subnet.Contains(reqIP) {
			return "", fmt.Errorf("preferred IP %q not within overlay subnet %s", preferredIP, p.subnet.String())
		}
		reqStr := reqIP.String()
		if holder, occupied := p.ipToPeer[reqStr]; occupied && holder != peerID {
			return "", fmt.Errorf("preferred IP %s is already allocated to peer %q", reqStr, holder)
		}

		lease := &IPLease{
			IP:          reqStr,
			PeerID:      peerID,
			AllocatedAt: now,
			ExpiresAt:   now.Add(p.leaseTTL),
			Active:      true,
		}
		p.leases[peerID] = lease
		p.ipToPeer[reqStr] = peerID
		return reqStr, nil
	}

	// Case 2: Scan for next available IP in subnet
	for u := p.startIP; u <= p.endIP; u++ {
		candidate := make(net.IP, 4)
		binary.BigEndian.PutUint32(candidate, u)
		candStr := candidate.String()

		if _, exists := p.ipToPeer[candStr]; !exists {
			lease := &IPLease{
				IP:          candStr,
				PeerID:      peerID,
				AllocatedAt: now,
				ExpiresAt:   now.Add(p.leaseTTL),
				Active:      true,
			}
			p.leases[peerID] = lease
			p.ipToPeer[candStr] = peerID
			return candStr, nil
		}
	}

	return "", errors.New("overlay subnet IP address pool exhausted")
}

// Release revokes and frees an allocated IP lease.
func (p *IPPool) Release(peerID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	lease, found := p.leases[peerID]
	if !found {
		return false
	}

	delete(p.ipToPeer, lease.IP)
	delete(p.leases, peerID)
	return true
}

// Renew extends the expiration time of an existing lease.
func (p *IPPool) Renew(peerID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	lease, found := p.leases[peerID]
	if !found || !lease.Active {
		return false
	}

	lease.ExpiresAt = time.Now().UTC().Add(p.leaseTTL)
	return true
}

// GetLease retrieves the active lease record for a peer.
func (p *IPPool) GetLease(peerID string) (IPLease, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	lease, found := p.leases[peerID]
	if !found {
		return IPLease{}, false
	}
	return *lease, true
}

// ListLeases returns a snapshot copy of all assigned leases.
func (p *IPPool) ListLeases() []IPLease {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]IPLease, 0, len(p.leases))
	for _, l := range p.leases {
		result = append(result, *l)
	}
	return result
}

// ReclaimExpired revokes leases that have exceeded their time-to-live.
func (p *IPPool) ReclaimExpired() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now().UTC()
	reclaimed := 0

	for peerID, lease := range p.leases {
		if now.After(lease.ExpiresAt) {
			delete(p.ipToPeer, lease.IP)
			delete(p.leases, peerID)
			reclaimed++
		}
	}

	return reclaimed
}

// ActiveCount returns the number of active peer leases (excluding gateway).
func (p *IPPool) ActiveCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.leases)
}
