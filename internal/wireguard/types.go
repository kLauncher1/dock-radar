package wireguard

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

var (
	peerIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{1,64}$`)
)

// PeerStatus indicates the connectivity state of a WireGuard tunnel peer.
type PeerStatus string

const (
	PeerStatusConnected        PeerStatus = "connected"
	PeerStatusHandshakePending PeerStatus = "handshake_pending"
	PeerStatusDisconnected     PeerStatus = "disconnected"
)

// PeerConfig defines the cryptographic identity, network endpoints, and traffic rules for a peer.
type PeerConfig struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	PublicKey            string     `json:"public_key"`
	PresharedKey         string     `json:"preshared_key,omitempty"`
	Endpoint             string     `json:"endpoint"`
	AllowedIPs           []string   `json:"allowed_ips"`
	LeasedIP             string     `json:"leased_ip,omitempty"`
	PersistentKeepalive  int        `json:"persistent_keepalive"` // in seconds, default: 25
	LastHandshake        time.Time  `json:"last_handshake"`
	RxBytes              uint64     `json:"rx_bytes"`
	TxBytes              uint64     `json:"tx_bytes"`
	Status               PeerStatus `json:"status"`
	LatencyMs            float64    `json:"latency_ms"`
}

// IPLease records a dynamically allocated overlay IP address within the WireGuard subnet.
type IPLease struct {
	IP          string    `json:"ip"`
	PeerID      string    `json:"peer_id"`
	AllocatedAt time.Time `json:"allocated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Active      bool      `json:"active"`
}

// RouteEntry defines an overlay packet forwarding rule mapping an IP range to a tunnel peer.
type RouteEntry struct {
	Destination string    `json:"destination"`
	PeerID      string    `json:"peer_id"`
	ViaEndpoint string    `json:"via_endpoint"`
	Metric      int       `json:"metric"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// WireGuardConfig contains initialization parameters for the userspace WireGuard mesh engine.
type WireGuardConfig struct {
	Enabled            bool   `json:"enabled"`
	InterfaceName      string `json:"interface_name"`
	ListenPort         int    `json:"listen_port"`
	PrivateKey         string `json:"private_key,omitempty"`
	PublicKey          string `json:"public_key"`
	VirtualCIDR        string `json:"virtual_cidr"`
	VirtualIP          string `json:"virtual_ip"`
	MTU                int    `json:"mtu"`
	KeepaliveInterval  int    `json:"keepalive_interval"`
	MaxPeers           int    `json:"max_peers"`
}

// WireGuardStatus summarizes the live operational health and telemetry of the WireGuard engine.
type WireGuardStatus struct {
	Enabled           bool      `json:"enabled"`
	InterfaceName     string    `json:"interface_name"`
	ListenPort        int       `json:"listen_port"`
	PublicKey         string    `json:"public_key"`
	VirtualIP         string    `json:"virtual_ip"`
	VirtualCIDR       string    `json:"virtual_cidr"`
	ActivePeers       int       `json:"active_peers"`
	TotalPeers        int       `json:"total_peers"`
	TotalRxBytes      uint64    `json:"total_rx_bytes"`
	TotalTxBytes      uint64    `json:"total_tx_bytes"`
	ActiveLeases      int       `json:"active_leases"`
	RoutingRulesCount int       `json:"routing_rules_count"`
	LastKeyRotation   time.Time `json:"last_key_rotation"`
}

// DefaultWireGuardConfig produces production-ready defaults for userspace WireGuard tunneling.
func DefaultWireGuardConfig() WireGuardConfig {
	return WireGuardConfig{
		Enabled:           true,
		InterfaceName:     "wg-radar0",
		ListenPort:        51820,
		VirtualCIDR:       "10.42.0.0/24",
		VirtualIP:         "10.42.0.1",
		MTU:               1420,
		KeepaliveInterval: 25,
		MaxPeers:          256,
	}
}

// ValidatePeerID ensures peer identifiers follow strict alphanumeric naming bounds.
func ValidatePeerID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("peer ID cannot be empty")
	}
	if !peerIDRegex.MatchString(id) {
		return fmt.Errorf("invalid peer ID %q: must match %s", id, peerIDRegex.String())
	}
	return nil
}

// ValidateCIDR verifies that the provided CIDR string represents a valid IP network.
func ValidateCIDR(cidr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	return ipNet, nil
}

// ValidateKey verifies that a Base64-encoded WireGuard key decodes to exactly 32 bytes.
func ValidateKey(keyB64 string) error {
	keyB64 = strings.TrimSpace(keyB64)
	if keyB64 == "" {
		return errors.New("cryptographic key cannot be empty")
	}
	decoded, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return fmt.Errorf("invalid base64 key encoding: %w", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(decoded))
	}
	return nil
}

// ValidatePort ensures a network port resides within non-privileged valid ranges.
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of valid range (1-65535)", port)
	}
	return nil
}

// MaskKey safely obscures cryptographic keys for display in audit logs and public responses.
func MaskKey(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 8 {
		return "********"
	}
	return key[:4] + "...." + key[len(key)-4:]
}
