package wireguard

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// KeyPair holds a generated Curve25519 (X25519) private/public keypair.
type KeyPair struct {
	PrivateKeyBase64 string `json:"private_key"`
	PublicKeyBase64  string `json:"public_key"`
	CreatedAt        time.Time `json:"created_at"`
}

// GenerateKeyPair generates a cryptographically secure RFC 7748 Curve25519 keypair.
func GenerateKeyPair() (*KeyPair, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 private key: %w", err)
	}

	pub := priv.PublicKey()

	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())
	pubB64 := base64.StdEncoding.EncodeToString(pub.Bytes())

	return &KeyPair{
		PrivateKeyBase64: privB64,
		PublicKeyBase64:  pubB64,
		CreatedAt:        time.Now().UTC(),
	}, nil
}

// GeneratePresharedKey generates a random 32-byte WireGuard preshared symmetric key.
func GeneratePresharedKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", fmt.Errorf("failed to read random bytes for PSK: %w", err)
	}
	defer Zeroize(key)
	return base64.StdEncoding.EncodeToString(key), nil
}

// DeriveSharedSecret computes the X25519 Diffie-Hellman shared secret between local private and remote public keys.
func DeriveSharedSecret(localPrivB64, remotePubB64 string) ([]byte, error) {
	privBytes, err := base64.StdEncoding.DecodeString(localPrivB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode local private key: %w", err)
	}
	defer Zeroize(privBytes)

	pubBytes, err := base64.StdEncoding.DecodeString(remotePubB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode remote public key: %w", err)
	}

	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 private key: %w", err)
	}

	pub, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 public key: %w", err)
	}

	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh computation failed: %w", err)
	}

	return shared, nil
}

// DeriveTunnelKey combines the ECDH shared secret with an optional preshared key (PSK) and context label.
func DeriveTunnelKey(sharedSecret []byte, pskB64 string, contextLabel string) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, errors.New("empty shared secret")
	}

	h := hmac.New(sha256.New, []byte("dock-radar-wireguard-v1:"+contextLabel))
	h.Write(sharedSecret)

	if pskB64 != "" {
		pskBytes, err := base64.StdEncoding.DecodeString(pskB64)
		if err != nil {
			return nil, fmt.Errorf("invalid preshared key base64: %w", err)
		}
		defer Zeroize(pskBytes)
		h.Write(pskBytes)
	}

	derived := h.Sum(nil)
	return derived, nil
}

// PacketCipher provides authenticated symmetric packet encryption and anti-replay defense.
type PacketCipher struct {
	key        []byte
	mu         sync.Mutex
	lastSeq    uint64
	replayWin  uint64 // 64-packet bitmap replay window
}

// NewPacketCipher creates an authenticated packet cipher from a 32-byte derived key.
func NewPacketCipher(key []byte) (*PacketCipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid cipher key length: expected 32 bytes, got %d", len(key))
	}
	keyCopy := make([]byte, 32)
	copy(keyCopy, key)
	return &PacketCipher{
		key: keyCopy,
	}, nil
}

// Close securely wipes the underlying symmetric key from memory.
func (pc *PacketCipher) Close() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	Zeroize(pc.key)
}

// EncryptPacket encrypts a plaintext packet, attaching a monotonically increasing sequence counter.
func (pc *PacketCipher) EncryptPacket(seq uint64, plaintext []byte) ([]byte, error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	block, err := aes.NewCipher(pc.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	// 12-byte nonce: 8 bytes sequence number big-endian + 4 bytes random jitter
	nonce := make([]byte, gcm.NonceSize())
	nonce[0] = byte(seq >> 56)
	nonce[1] = byte(seq >> 48)
	nonce[2] = byte(seq >> 40)
	nonce[3] = byte(seq >> 32)
	nonce[4] = byte(seq >> 24)
	nonce[5] = byte(seq >> 16)
	nonce[6] = byte(seq >> 8)
	nonce[7] = byte(seq)

	if _, err := io.ReadFull(rand.Reader, nonce[8:]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce entropy: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Wire format: 12 bytes nonce + ciphertext
	out := make([]byte, len(nonce)+len(ciphertext))
	copy(out, nonce)
	copy(out[len(nonce):], ciphertext)

	return out, nil
}

// DecryptPacket authenticates and decrypts an encrypted wire packet, rejecting replay attacks.
func (pc *PacketCipher) DecryptPacket(packet []byte) (uint64, []byte, error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if len(packet) < 28 { // 12 nonce + 16 GCM tag
		return 0, nil, errors.New("packet too short for GCM authentication")
	}

	nonce := packet[:12]
	ciphertext := packet[12:]

	seq := (uint64(nonce[0]) << 56) |
		(uint64(nonce[1]) << 48) |
		(uint64(nonce[2]) << 40) |
		(uint64(nonce[3]) << 32) |
		(uint64(nonce[4]) << 24) |
		(uint64(nonce[5]) << 16) |
		(uint64(nonce[6]) << 8) |
		uint64(nonce[7])

	// Anti-replay check
	if pc.lastSeq > 0 {
		if seq <= pc.lastSeq {
			diff := pc.lastSeq - seq
			if diff >= 64 {
				return 0, nil, fmt.Errorf("packet sequence %d too old (current: %d)", seq, pc.lastSeq)
			}
			if (pc.replayWin & (1 << diff)) != 0 {
				return 0, nil, fmt.Errorf("replay attack detected: packet %d already processed", seq)
			}
		}
	}

	block, err := aes.NewCipher(pc.key)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("packet authentication failed: %w", err)
	}

	// Update sliding window on successful authentication
	if seq > pc.lastSeq {
		diff := seq - pc.lastSeq
		if diff >= 64 {
			pc.replayWin = 1
		} else {
			pc.replayWin = (pc.replayWin << diff) | 1
		}
		pc.lastSeq = seq
	} else {
		diff := pc.lastSeq - seq
		pc.replayWin |= (1 << diff)
	}

	return seq, plaintext, nil
}

// Zeroize securely overwrites sensitive byte slices with zero bytes to prevent memory disclosure.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ConstantTimeCompareString performs constant-time comparison of two strings to prevent timing attacks.
func ConstantTimeCompareString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
