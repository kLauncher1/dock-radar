package vault

import (
	"bytes"
	"testing"
)

func TestZeroize(t *testing.T) {
	buf := []byte("super-secret-password-1234")
	Zeroize(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("expected byte at index %d to be 0, got %d", i, b)
		}
	}
}

func TestConstantTimeCompareString(t *testing.T) {
	if !ConstantTimeCompareString("test-secret-token", "test-secret-token") {
		t.Errorf("expected matching strings to return true")
	}
	if ConstantTimeCompareString("test-secret-token", "test-secret-tokeN") {
		t.Errorf("expected mismatched strings to return false")
	}
	if ConstantTimeCompareString("short", "longer-string") {
		t.Errorf("expected mismatched length strings to return false")
	}
}

func TestIDGenerators(t *testing.T) {
	keyID := GenerateKeyID()
	if len(keyID) < 10 || keyID[:4] != "key_" {
		t.Errorf("unexpected key ID format: %s", keyID)
	}

	secretID := GenerateSecretID()
	if err := ValidateSecretID(secretID); err != nil {
		t.Errorf("generated secret ID failed validation: %v", err)
	}

	tokenID := GenerateTokenID()
	if err := ValidateTokenID(tokenID); err != nil {
		t.Errorf("generated token ID failed validation: %v", err)
	}

	leaseID := GenerateLeaseID()
	if err := ValidateLeaseID(leaseID); err != nil {
		t.Errorf("generated lease ID failed validation: %v", err)
	}
}

func TestDeriveHardwareRootKey(t *testing.T) {
	salt := []byte("test-salt-12345678")
	machineID := "machine-uuid-alpha-99"

	key1, err := DeriveHardwareRootKey(salt, machineID, 50)
	if err != nil {
		t.Fatalf("failed to derive hardware key: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}

	// Should be deterministic
	key2, err := DeriveHardwareRootKey(salt, machineID, 50)
	if err != nil {
		t.Fatalf("failed to derive hardware key 2: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatalf("expected deterministic hardware key derivation")
	}

	// Different machine should produce different key
	key3, _ := DeriveHardwareRootKey(salt, "machine-uuid-beta-100", 50)
	if bytes.Equal(key1, key3) {
		t.Fatalf("expected different key for different machine ID")
	}
}

func TestEncryptDecryptSecret_Roundtrip(t *testing.T) {
	key, err := GenerateAES256Key()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	defer Zeroize(key)

	plaintext := []byte("postgres://admin:topsecret123@prod-db.internal:5432/core")
	cipherB64, nonceHex, err := EncryptSecret(key, plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt secret: %v", err)
	}

	decrypted, err := DecryptSecret(key, cipherB64, nonceHex)
	if err != nil {
		t.Fatalf("failed to decrypt secret: %v", err)
	}
	defer Zeroize(decrypted)

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted plaintext did not match original: got %s", string(decrypted))
	}
}

func TestDecryptSecret_Tampering(t *testing.T) {
	key, _ := GenerateAES256Key()
	defer Zeroize(key)

	plaintext := []byte("sensitive-api-token-999")
	cipherB64, nonceHex, _ := EncryptSecret(key, plaintext)

	// Tampered ciphertext
	tamperedCipher := cipherB64[:len(cipherB64)-4] + "AAAA"
	_, err := DecryptSecret(key, tamperedCipher, nonceHex)
	if err == nil {
		t.Fatalf("expected decryption error on tampered ciphertext, got nil")
	}

	// Tampered nonce
	tamperedNonce := "000000000000000000000000"
	_, err = DecryptSecret(key, cipherB64, tamperedNonce)
	if err == nil {
		t.Fatalf("expected decryption error on tampered nonce, got nil")
	}

	// Wrong key
	wrongKey, _ := GenerateAES256Key()
	defer Zeroize(wrongKey)
	_, err = DecryptSecret(wrongKey, cipherB64, nonceHex)
	if err == nil {
		t.Fatalf("expected decryption error on wrong key, got nil")
	}
}

func TestHMACSHA256(t *testing.T) {
	secret := []byte("replication-shared-key-32bytes!")
	data := []byte("dock-radar-cluster-sync-payload-v1")

	sig := ComputeHMACSHA256(secret, data)
	if len(sig) != 64 {
		t.Fatalf("expected 64-character hex signature, got %d", len(sig))
	}

	if !VerifyHMACSHA256(secret, data, sig) {
		t.Fatalf("expected valid signature verification to pass")
	}

	// Tampered data
	if VerifyHMACSHA256(secret, []byte("tampered-data"), sig) {
		t.Fatalf("expected verification to fail on tampered data")
	}

	// Wrong secret
	if VerifyHMACSHA256([]byte("wrong-secret"), data, sig) {
		t.Fatalf("expected verification to fail on wrong secret")
	}
}
