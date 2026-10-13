package system

import (
	"testing"
)

func TestCollectTelemetry(t *testing.T) {
	metrics := CollectTelemetry()

	if metrics.Hostname == "" {
		t.Errorf("expected non-empty hostname")
	}
	if metrics.NumCPU <= 0 {
		t.Errorf("expected NumCPU > 0, got %d", metrics.NumCPU)
	}
	if metrics.OS == "" {
		t.Errorf("expected non-empty OS string")
	}
	if metrics.AllocMB < 0 {
		t.Errorf("expected non-negative AllocMB, got %f", metrics.AllocMB)
	}
}
