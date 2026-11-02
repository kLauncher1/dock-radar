package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

var timeNow = time.Now

// Zeroize securely overwrites sensitive memory buffers with zero bytes.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ConstantTimeCompareString performs constant-time comparison of two strings.
func ConstantTimeCompareString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// GenerateRandomBytes returns securely generated random bytes from crypto/rand.
func GenerateRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("byte count must be positive")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return buf, nil
}

// GenerateKeyID returns a random identifier for master encryption keys.
func GenerateKeyID() string {
	b, err := GenerateRandomBytes(8)
	if err != nil {
		return fmt.Sprintf("key_%x", sha256.Sum256([]byte(fmt.Sprintf("%d", timeNow().UnixNano()))))[:20]
	}
	return "key_" + hex.EncodeToString(b)
}

// GenerateSecretID returns a random unique identifier for stored secrets.
func GenerateSecretID() string {
	b, err := GenerateRandomBytes(8)
	if err != nil {
		return fmt.Sprintf("sec_%x", sha256.Sum256([]byte(fmt.Sprintf("%d", timeNow().UnixNano()))))[:20]
	}
	return "sec_" + hex.EncodeToString(b)
}

// GenerateTokenID returns a random unique identifier for cluster join tokens.
func GenerateTokenID() string {
	b, err := GenerateRandomBytes(8)
	if err != nil {
		return fmt.Sprintf("tok_%x", sha256.Sum256([]byte(fmt.Sprintf("%d", timeNow().UnixNano()))))[:20]
	}
	return "tok_" + hex.EncodeToString(b)
}

// GenerateLeaseID returns a random unique identifier for ephemeral leases.
func GenerateLeaseID() string {
	b, err := GenerateRandomBytes(8)
	if err != nil {
		return fmt.Sprintf("lse_%x", sha256.Sum256([]byte(fmt.Sprintf("%d", timeNow().UnixNano()))))[:20]
	}
	return "lse_" + hex.EncodeToString(b)
}

// GenerateAES256Key generates a cryptographically secure 256-bit symmetric key.
func GenerateAES256Key() ([]byte, error) {
	return GenerateRandomBytes(32)
}

// DeriveHardwareRootKey derives a 256-bit AES master key from hardware root seed/machineID.
// It uses multi-round HMAC-SHA256 key derivation with salt.
func DeriveHardwareRootKey(salt []byte, machineID string, iterations int) ([]byte, error) {
	if iterations <= 0 {
		iterations = 10000
	}
	if len(salt) == 0 {
		salt = []byte("dock-radar-vault-hardware-salt-v1")
	}

	h := hmac.New(sha256.New, salt)
	h.Write([]byte("dock-radar-hw-root-kdf:" + machineID))
	derived := h.Sum(nil)

	// Key stretching iterations
	block := make([]byte, len(derived))
	copy(block, derived)
	for i := 1; i < iterations; i++ {
		h.Reset()
		h.Write(block)
		block = h.Sum(nil)
		for j := range derived {
			derived[j] ^= block[j]
		}
	}

	return derived, nil
}

// EncryptSecret encrypts plaintext using AES-256-GCM with a fresh 12-byte nonce.
// Returns Base64-encoded ciphertext (including 16-byte auth tag) and Hex-encoded nonce.
func EncryptSecret(key []byte, plaintext []byte) (string, string, error) {
	if len(key) != 32 {
		return "", "", errors.New("invalid AES key length: must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("failed to create GCM block: %w", err)
	}

	nonce, err := GenerateRandomBytes(gcm.NonceSize())
	if err != nil {
		return "", "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	ciphertextB64 := base64.StdEncoding.EncodeToString(sealed)
	nonceHex := hex.EncodeToString(nonce)

	return ciphertextB64, nonceHex, nil
}

// DecryptSecret decrypts and authenticates AES-256-GCM ciphertext using the specified key and nonce.
// It returns the decrypted plaintext bytes. Caller is responsible for Zeroize on plaintext if needed.
func DecryptSecret(key []byte, ciphertextB64 string, nonceHex string) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid AES key length: must be 32 bytes for AES-256")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 ciphertext: %w", err)
	}

	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: got %d, expected %d", len(nonce), gcm.NonceSize())
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// ComputeHMACSHA256 generates hex-encoded HMAC-SHA256 signature over data.
func ComputeHMACSHA256(secret []byte, data []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMACSHA256 validates HMAC-SHA256 signature in constant time.
func VerifyHMACSHA256(secret []byte, data []byte, expectedHex string) bool {
	actualHex := ComputeHMACSHA256(secret, data)
	return ConstantTimeCompareString(actualHex, expectedHex)
}
