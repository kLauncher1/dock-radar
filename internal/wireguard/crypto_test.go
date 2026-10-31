package wireguard

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if kp.PrivateKeyBase64 == "" || kp.PublicKeyBase64 == "" {
		t.Errorf("empty keys generated")
	}
	if err := ValidateKey(kp.PrivateKeyBase64); err != nil {
		t.Errorf("private key validation failed: %v", err)
	}
	if err := ValidateKey(kp.PublicKeyBase64); err != nil {
		t.Errorf("public key validation failed: %v", err)
	}
}

func TestGeneratePresharedKey(t *testing.T) {
	psk, err := GeneratePresharedKey()
	if err != nil {
		t.Fatalf("GeneratePresharedKey failed: %v", err)
	}
	if err := ValidateKey(psk); err != nil {
		t.Errorf("preshared key validation failed: %v", err)
	}
}

func TestDeriveSharedSecret_ValidAndInvalid(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	aliceShared, err := DeriveSharedSecret(alice.PrivateKeyBase64, bob.PublicKeyBase64)
	if err != nil {
		t.Fatalf("Alice ECDH failed: %v", err)
	}

	bobShared, err := DeriveSharedSecret(bob.PrivateKeyBase64, alice.PublicKeyBase64)
	if err != nil {
		t.Fatalf("Bob ECDH failed: %v", err)
	}

	if !bytes.Equal(aliceShared, bobShared) {
		t.Errorf("ECDH shared secrets mismatch between Alice and Bob")
	}

	// Invalid key
	if _, err := DeriveSharedSecret("bad-key", bob.PublicKeyBase64); err == nil {
		t.Errorf("expected error for bad private key")
	}
}

func TestPacketCipher_EncryptDecrypt(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	shared, _ := DeriveSharedSecret(alice.PrivateKeyBase64, bob.PublicKeyBase64)
	key, err := DeriveTunnelKey(shared, "", "test-session")
	if err != nil {
		t.Fatalf("DeriveTunnelKey failed: %v", err)
	}

	aliceCipher, err := NewPacketCipher(key)
	if err != nil {
		t.Fatalf("NewPacketCipher failed: %v", err)
	}
	defer aliceCipher.Close()

	bobCipher, err := NewPacketCipher(key)
	if err != nil {
		t.Fatalf("NewPacketCipher failed: %v", err)
	}
	defer bobCipher.Close()

	message := []byte("hello WireGuard overlay packet from Alice!")
	ciphertext, err := aliceCipher.EncryptPacket(1, message)
	if err != nil {
		t.Fatalf("EncryptPacket failed: %v", err)
	}

	seq, decrypted, err := bobCipher.DecryptPacket(ciphertext)
	if err != nil {
		t.Fatalf("DecryptPacket failed: %v", err)
	}
	if seq != 1 {
		t.Errorf("expected sequence 1, got %d", seq)
	}
	if !bytes.Equal(decrypted, message) {
		t.Errorf("decrypted text mismatch: expected %q, got %q", string(message), string(decrypted))
	}
}

func TestPacketCipher_AntiReplay(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	sender, _ := NewPacketCipher(key)
	receiver, _ := NewPacketCipher(key)
	defer sender.Close()
	defer receiver.Close()

	pkt1, err := sender.EncryptPacket(1, []byte("packet 1"))
	if err != nil {
		t.Fatal(err)
	}
	pkt2, err := sender.EncryptPacket(2, []byte("packet 2"))
	if err != nil {
		t.Fatal(err)
	}

	// First reception ok
	if _, _, err := receiver.DecryptPacket(pkt1); err != nil {
		t.Fatalf("packet 1 failed: %v", err)
	}
	if _, _, err := receiver.DecryptPacket(pkt2); err != nil {
		t.Fatalf("packet 2 failed: %v", err)
	}

	// Replay packet 1 -> must fail
	if _, _, err := receiver.DecryptPacket(pkt1); err == nil {
		t.Errorf("expected replay attack error for packet 1")
	}

	// Replay packet 2 -> must fail
	if _, _, err := receiver.DecryptPacket(pkt2); err == nil {
		t.Errorf("expected replay attack error for packet 2")
	}
}

func TestZeroize(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5}
	Zeroize(buf)
	for _, b := range buf {
		if b != 0 {
			t.Errorf("expected zero byte, got %d", b)
		}
	}
}

func TestConstantTimeCompareString(t *testing.T) {
	if !ConstantTimeCompareString("test-secret", "test-secret") {
		t.Errorf("expected strings to match")
	}
	if ConstantTimeCompareString("test-secret", "other-secret") {
		t.Errorf("expected strings to mismatch")
	}
}
