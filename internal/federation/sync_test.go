package federation

import (
	"testing"
	"time"
)

func TestComputeInventoryDigest(t *testing.T) {
	containers := []FederatedContainer{
		{ID: "c1", Name: "web-server", Image: "nginx:alpine", State: "running", CPUPercent: 2.5, MemoryMB: 64.0},
		{ID: "c2", Name: "database", Image: "postgres:16", State: "running", CPUPercent: 12.0, MemoryMB: 512.0},
	}

	d1 := ComputeInventoryDigest("us-east-1", containers)
	if d1.ContainerNum != 2 || d1.DigestHex == "" {
		t.Fatalf("invalid digest: %+v", d1)
	}

	// Permuting order should result in identical digest
	reversed := []FederatedContainer{containers[1], containers[0]}
	d2 := ComputeInventoryDigest("us-east-1", reversed)
	if d1.DigestHex != d2.DigestHex {
		t.Fatalf("expected deterministic digest regardless of container slice order, got %s vs %s", d1.DigestHex, d2.DigestHex)
	}

	// Changing state should alter digest
	containers[0].State = "exited"
	d3 := ComputeInventoryDigest("us-east-1", containers)
	if d1.DigestHex == d3.DigestHex {
		t.Fatal("expected different digest when container state changes, but got same")
	}
}

func TestDeltaSyncEngine_Lifecycle(t *testing.T) {
	engine := NewDeltaSyncEngine("us-east-1")

	localContainers := []FederatedContainer{
		{ID: "c1", Name: "app-api", Image: "golang:1.24", State: "running", CPUPercent: 1.0, MemoryMB: 128.0},
		{ID: "c2", Name: "redis-cache", Image: "redis:alpine", State: "running", CPUPercent: 0.5, MemoryMB: 32.0},
	}
	digest := engine.SetLocalContainers(localContainers)
	if digest.ContainerNum != 2 {
		t.Fatalf("expected 2 containers in digest, got %d", digest.ContainerNum)
	}

	// 1. Initial delta generation for remote region without cached digest (FullSync)
	payload, err := engine.ComputeDelta("eu-west-1", "")
	if err != nil {
		t.Fatalf("compute delta error: %v", err)
	}
	if !payload.IsFullSync || len(payload.Added) != 2 {
		t.Fatalf("expected full sync with 2 added containers, got %+v", payload)
	}

	// 2. Receiving side applies delta
	remoteEngine := NewDeltaSyncEngine("eu-west-1")
	added, updated, removed, err := remoteEngine.ApplyDelta(payload)
	if err != nil {
		t.Fatalf("apply delta error: %v", err)
	}
	if added != 2 || updated != 0 || removed != 0 {
		t.Fatalf("unexpected counts: added=%d, updated=%d, removed=%d", added, updated, removed)
	}

	all := remoteEngine.GetAllContainers()
	if len(all) != 2 {
		t.Fatalf("expected 2 remote containers, got %d", len(all))
	}

	// 3. Compute delta with identical remote digest (No changes -> CompressedBytes should be minimal)
	noopPayload, err := engine.ComputeDelta("eu-west-1", digest.DigestHex)
	if err != nil {
		t.Fatalf("noop delta error: %v", err)
	}
	if len(noopPayload.Added) != 0 || len(noopPayload.Updated) != 0 {
		t.Fatalf("expected empty delta when digests match, got %+v", noopPayload)
	}

	totalBytes, savedBytes, eff, lastSync := remoteEngine.Telemetry()
	if totalBytes == 0 || savedBytes == 0 || eff <= 0.0 || lastSync.IsZero() {
		t.Fatalf("unexpected telemetry: total=%d, saved=%d, eff=%.2f, lastSync=%v", totalBytes, savedBytes, eff, lastSync)
	}
}

func TestGzipCompressionHelpers(t *testing.T) {
	type testMessage struct {
		ID        string    `json:"id"`
		Content   string    `json:"content"`
		Timestamp time.Time `json:"timestamp"`
	}

	original := testMessage{
		ID:        "msg-99",
		Content:   "This is a high-volume WAN state replication packet test that compresses well.",
		Timestamp: time.Now().UTC(),
	}

	compressed, err := CompressPayload(original)
	if err != nil {
		t.Fatalf("compression failed: %v", err)
	}
	if len(compressed) == 0 {
		t.Fatal("empty compressed payload")
	}

	var restored testMessage
	if err := DecompressPayload(compressed, &restored); err != nil {
		t.Fatalf("decompression failed: %v", err)
	}
	if restored.ID != original.ID || restored.Content != original.Content {
		t.Fatalf("restored data mismatch: got %+v, want %+v", restored, original)
	}
}
