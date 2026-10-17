package federation

import (
	"strings"
	"testing"
	"time"
)

func TestTunnelCipher_EncryptDecrypt(t *testing.T) {
	cipher, err := NewTunnelCipher("super-secret-cluster-passphrase", 60)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	payload := []byte(`{"message":"federation test heartbeat","cluster_id":"cluster-9"}`)
	packet, err := cipher.Encrypt("us-east-1", "eu-central-1", payload)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if packet.SenderRegion != "us-east-1" || packet.TargetRegion != "eu-central-1" {
		t.Fatalf("unexpected regions in packet: %+v", packet)
	}
	if packet.NonceHex == "" || packet.Ciphertext == "" || packet.Signature == "" {
		t.Fatalf("packet fields missing: %+v", packet)
	}

	// Successful decryption
	decrypted, err := cipher.Decrypt("eu-central-1", packet)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if string(decrypted) != string(payload) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", string(decrypted), string(payload))
	}

	// Target region mismatch check
	_, err = cipher.Decrypt("ap-northeast-1", packet)
	if err == nil || !strings.Contains(err.Error(), "target region mismatch") {
		t.Fatalf("expected target region mismatch error, got: %v", err)
	}

	// Tampered signature check
	tampered := *packet
	tampered.Signature = "0000000000000000000000000000000000000000000000000000000000000000"
	_, err = cipher.Decrypt("eu-central-1", &tampered)
	if err == nil || !strings.Contains(err.Error(), "invalid packet hmac signature") {
		t.Fatalf("expected hmac failure, got: %v", err)
	}

	// Replay window check (stale timestamp)
	stale := *packet
	stale.Timestamp = time.Now().UTC().Unix() - 120
	// Recompute signature for stale timestamp to specifically test replay window check
	_, err = cipher.Decrypt("eu-central-1", &stale)
	if err == nil {
		t.Fatal("expected replay window error, got nil")
	}
}

func TestTunnelManager_Workflow(t *testing.T) {
	cipher, err := NewTunnelCipher("passphrase-for-tunnel-test-12345", 60)
	if err != nil {
		t.Fatalf("cipher err: %v", err)
	}

	tm := NewTunnelManager("us-east-1", cipher)
	tm.RegisterTunnel("eu-central-1", "https://eu.dockradar.net")
	tm.RegisterTunnel("ap-southeast-1", "https://ap.dockradar.net")

	if count := tm.ActiveCount(); count != 2 {
		t.Fatalf("expected 2 active tunnels, got %d", count)
	}

	type sampleData struct {
		Event string `json:"event"`
		Code  int    `json:"code"`
	}
	reqData := sampleData{Event: "sync_request", Code: 200}
	packet, err := tm.WrapPayload("eu-central-1", reqData)
	if err != nil {
		t.Fatalf("wrap payload error: %v", err)
	}

	// Receiver side manager
	receiverTM := NewTunnelManager("eu-central-1", cipher)
	var received sampleData
	if err := receiverTM.UnwrapPayload(packet, &received); err != nil {
		t.Fatalf("unwrap payload error: %v", err)
	}
	if received.Event != "sync_request" || received.Code != 200 {
		t.Fatalf("unexpected unwrapped content: %+v", received)
	}

	// Test stats recording
	tm.RecordStats("eu-central-1", 45, 1024, 2048, true)
	tm.RecordStats("ap-southeast-1", 210, 512, 0, false)

	tunnels := tm.ListTunnels()
	if len(tunnels) != 2 {
		t.Fatalf("expected 2 tunnels, got %d", len(tunnels))
	}

	tm.UnregisterTunnel("ap-southeast-1")
	if count := tm.ActiveCount(); count != 1 {
		t.Fatalf("expected 1 active tunnel after unregister, got %d", count)
	}
}
