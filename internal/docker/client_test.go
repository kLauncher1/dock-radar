package docker

import (
	"testing"
)

func TestClientInitialization(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatalf("expected non-nil client")
	}

	// Should safely return a valid status even when daemon is offline
	status := client.InspectContainers()
	if status.CheckedAt.IsZero() {
		t.Errorf("expected non-zero CheckedAt timestamp")
	}
	if status.TotalCount < 0 {
		t.Errorf("expected non-negative TotalCount")
	}
}
