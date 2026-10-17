package federation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// EncryptedPacket represents an authenticated wire payload passed across cross-region tunnels.
type EncryptedPacket struct {
	SenderRegion string `json:"sender_region"`
	TargetRegion string `json:"target_region"`
	Timestamp    int64  `json:"timestamp"`
	NonceHex     string `json:"nonce_hex"`
	Ciphertext   string `json:"ciphertext"`
	Signature    string `json:"signature"`
}

// TunnelCipher provides AES-256-GCM authenticated encryption and replay defense.
type TunnelCipher struct {
	key       []byte
	ttlSec    int64
	keySecret string
}

// NewTunnelCipher initializes an AES-256-GCM cipher using SHA-256 key derivation.
func NewTunnelCipher(sharedSecret string, ttlSec int64) (*TunnelCipher, error) {
	if len(sharedSecret) < 8 {
		return nil, errors.New("shared secret must be at least 8 characters")
	}
	if ttlSec <= 0 {
		ttlSec = 60
	}
	derivedKey := sha256.Sum256([]byte(sharedSecret))
	return &TunnelCipher{
		key:       derivedKey[:],
		ttlSec:    ttlSec,
		keySecret: sharedSecret,
	}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM and generates an HMAC-SHA256 signature.
func (c *TunnelCipher) Encrypt(sender, target string, plaintext []byte) (*EncryptedPacket, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	now := time.Now().UTC().Unix()

	nonceHex := hex.EncodeToString(nonce)
	cipherHex := hex.EncodeToString(ciphertext)

	mac := hmac.New(sha256.New, c.key)
	fmt.Fprintf(mac, "%s:%s:%d:%s:%s", sender, target, now, nonceHex, cipherHex)
	sigHex := hex.EncodeToString(mac.Sum(nil))

	return &EncryptedPacket{
		SenderRegion: sender,
		TargetRegion: target,
		Timestamp:    now,
		NonceHex:     nonceHex,
		Ciphertext:   cipherHex,
		Signature:    sigHex,
	}, nil
}

// Decrypt verifies signature, checks packet freshness to prevent replays, and decrypts ciphertext.
func (c *TunnelCipher) Decrypt(expectedTarget string, packet *EncryptedPacket) ([]byte, error) {
	if packet == nil {
		return nil, errors.New("nil packet")
	}
	if expectedTarget != "" && packet.TargetRegion != expectedTarget {
		return nil, fmt.Errorf("target region mismatch: expected %q, got %q", expectedTarget, packet.TargetRegion)
	}

	now := time.Now().UTC().Unix()
	if diff := now - packet.Timestamp; diff > c.ttlSec || diff < -c.ttlSec {
		return nil, fmt.Errorf("packet timestamp outside replay window (%d seconds skew)", diff)
	}

	mac := hmac.New(sha256.New, c.key)
	fmt.Fprintf(mac, "%s:%s:%d:%s:%s", packet.SenderRegion, packet.TargetRegion, packet.Timestamp, packet.NonceHex, packet.Ciphertext)
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(packet.Signature), []byte(expectedSig)) != 1 {
		return nil, errors.New("invalid packet hmac signature")
	}

	nonce, err := hex.DecodeString(packet.NonceHex)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce hex: %w", err)
	}

	ciphertext, err := hex.DecodeString(packet.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext hex: %w", err)
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption authentication failed: %w", err)
	}

	return plaintext, nil
}

// OverlayTunnel tracks the live metrics and state of a cross-region tunnel.
type OverlayTunnel struct {
	RemoteRegionID string    `json:"remote_region_id"`
	Endpoint       string    `json:"endpoint"`
	Status         string    `json:"status"` // "active", "degraded", "closed"
	LastHandshake  time.Time `json:"last_handshake"`
	BytesSent      int64     `json:"bytes_sent"`
	BytesReceived  int64     `json:"bytes_received"`
	RTTMs          int64     `json:"rtt_ms"`
	PacketsSent    int64     `json:"packets_sent"`
	PacketsLost    int64     `json:"packets_lost"`
}

// TunnelManager coordinates active overlay tunnels.
type TunnelManager struct {
	mu          sync.RWMutex
	localRegion string
	cipher      *TunnelCipher
	tunnels     map[string]*OverlayTunnel
}

// NewTunnelManager constructs an overlay tunnel manager.
func NewTunnelManager(localRegion string, cipher *TunnelCipher) *TunnelManager {
	return &TunnelManager{
		localRegion: localRegion,
		cipher:      cipher,
		tunnels:     make(map[string]*OverlayTunnel),
	}
}

// RegisterTunnel creates or updates an overlay tunnel to a remote region.
func (tm *TunnelManager) RegisterTunnel(regionID, endpoint string) *OverlayTunnel {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tun, exists := tm.tunnels[regionID]
	if !exists {
		tun = &OverlayTunnel{
			RemoteRegionID: regionID,
			Endpoint:       endpoint,
			Status:         "active",
			LastHandshake:  time.Now().UTC(),
		}
		tm.tunnels[regionID] = tun
	} else {
		tun.Endpoint = endpoint
		tun.Status = "active"
	}
	return tun
}

// UnregisterTunnel removes a tunnel from registry.
func (tm *TunnelManager) UnregisterTunnel(regionID string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	delete(tm.tunnels, regionID)
}

// WrapPayload encrypts arbitrary data for a target region.
func (tm *TunnelManager) WrapPayload(targetRegion string, data any) (*EncryptedPacket, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("payload serialization error: %w", err)
	}
	return tm.cipher.Encrypt(tm.localRegion, targetRegion, raw)
}

// UnwrapPayload decrypts and verifies an incoming encrypted packet.
func (tm *TunnelManager) UnwrapPayload(packet *EncryptedPacket, target any) error {
	plaintext, err := tm.cipher.Decrypt(tm.localRegion, packet)
	if err != nil {
		return err
	}
	return json.Unmarshal(plaintext, target)
}

// RecordStats updates tunnel operational metrics.
func (tm *TunnelManager) RecordStats(regionID string, rttMs int64, bytesSent, bytesRecv int64, success bool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tun, exists := tm.tunnels[regionID]
	if !exists {
		return
	}
	tun.LastHandshake = time.Now().UTC()
	tun.BytesSent += bytesSent
	tun.BytesReceived += bytesRecv
	tun.PacketsSent++
	if success {
		tun.RTTMs = rttMs
		tun.Status = "active"
	} else {
		tun.PacketsLost++
		tun.Status = "degraded"
	}
}

// ListTunnels returns a snapshot of all active overlay tunnels.
func (tm *TunnelManager) ListTunnels() []OverlayTunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	result := make([]OverlayTunnel, 0, len(tm.tunnels))
	for _, tun := range tm.tunnels {
		result = append(result, *tun)
	}
	return result
}

// ActiveCount returns count of active tunnels.
func (tm *TunnelManager) ActiveCount() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	count := 0
	for _, tun := range tm.tunnels {
		if tun.Status == "active" {
			count++
		}
	}
	return count
}
