package wireguard

import (
	"net"
	"testing"
)

func TestRouter_RegisterAndLookup(t *testing.T) {
	r := NewRouter()

	err := r.RegisterPeerRoutes("peer-alpha", []string{"10.42.0.2/32", "192.168.10.0/24"})
	if err != nil {
		t.Fatalf("RegisterPeerRoutes failed: %v", err)
	}

	err = r.RegisterPeerRoutes("peer-beta", []string{"10.42.0.3/32"})
	if err != nil {
		t.Fatalf("RegisterPeerRoutes failed: %v", err)
	}

	// Lookup 10.42.0.2 -> peer-alpha
	peer, found := r.LookupPeer(net.ParseIP("10.42.0.2"))
	if !found || peer != "peer-alpha" {
		t.Errorf("expected peer-alpha, got %q (found: %v)", peer, found)
	}

	// Lookup 192.168.10.45 -> peer-alpha
	peer, found = r.LookupPeer(net.ParseIP("192.168.10.45"))
	if !found || peer != "peer-alpha" {
		t.Errorf("expected peer-alpha, got %q (found: %v)", peer, found)
	}

	// Lookup 10.42.0.3 -> peer-beta
	peer, found = r.LookupPeer(net.ParseIP("10.42.0.3"))
	if !found || peer != "peer-beta" {
		t.Errorf("expected peer-beta, got %q (found: %v)", peer, found)
	}

	// Unrouted IP
	_, found = r.LookupPeer(net.ParseIP("8.8.8.8"))
	if found {
		t.Errorf("expected 8.8.8.8 to have no route")
	}

	// Remove peer-alpha
	r.RemovePeerRoutes("peer-alpha")
	_, found = r.LookupPeer(net.ParseIP("10.42.0.2"))
	if found {
		t.Errorf("expected 10.42.0.2 route to be removed")
	}
}

func TestRouter_ValidateIngress_ZeroTrust(t *testing.T) {
	r := NewRouter()
	_ = r.RegisterPeerRoutes("peer-alice", []string{"10.42.0.10/32"})

	// Packet with source 10.42.0.10 from peer-alice -> permitted
	if !r.ValidateIngress("peer-alice", net.ParseIP("10.42.0.10")) {
		t.Errorf("expected ingress to be valid for matching allowed IP")
	}

	// Spoofed packet with source 10.42.0.99 from peer-alice -> dropped
	if r.ValidateIngress("peer-alice", net.ParseIP("10.42.0.99")) {
		t.Errorf("expected ingress to be rejected for spoofed source IP")
	}

	// Unknown peer
	if r.ValidateIngress("peer-unknown", net.ParseIP("10.42.0.10")) {
		t.Errorf("expected ingress to be rejected for unknown peer")
	}
}

func TestRouter_EndpointRoaming(t *testing.T) {
	r := NewRouter()
	_ = r.SetInitialEndpoint("peer-1", "192.0.2.1:51820")

	ep := r.GetPeerEndpoint("peer-1")
	if ep == nil || ep.String() != "192.0.2.1:51820" {
		t.Errorf("expected 192.0.2.1:51820, got %v", ep)
	}

	// Endpoint roaming to new NAT address
	newAddr, _ := net.ResolveUDPAddr("udp", "198.51.100.5:41234")
	r.UpdatePeerEndpoint("peer-1", newAddr)

	updated := r.GetPeerEndpoint("peer-1")
	if updated == nil || updated.String() != "198.51.100.5:41234" {
		t.Errorf("expected roamed address 198.51.100.5:41234, got %v", updated)
	}
}

func TestParsePacketHeaders(t *testing.T) {
	// Construct minimal 20-byte IPv4 packet
	pkt := make([]byte, 20)
	pkt[0] = 0x45 // Version 4, IHL 5
	// Source IP: 10.42.0.5
	copy(pkt[12:16], []byte{10, 42, 0, 5})
	// Destination IP: 10.42.0.1
	copy(pkt[16:20], []byte{10, 42, 0, 1})

	src, dst, err := ParsePacketHeaders(pkt)
	if err != nil {
		t.Fatalf("ParsePacketHeaders failed: %v", err)
	}
	if src.String() != "10.42.0.5" {
		t.Errorf("expected src 10.42.0.5, got %s", src.String())
	}
	if dst.String() != "10.42.0.1" {
		t.Errorf("expected dst 10.42.0.1, got %s", dst.String())
	}

	// Invalid short packet
	if _, _, err := ParsePacketHeaders([]byte{1, 2, 3}); err == nil {
		t.Errorf("expected error on short packet")
	}
}
