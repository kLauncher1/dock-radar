package canary

import (
	"testing"
)

func TestDefaultCanaryConfig(t *testing.T) {
	cfg := DefaultCanaryConfig()
	if !cfg.Enabled {
		t.Fatalf("expected DefaultCanaryConfig.Enabled to be true")
	}
	if cfg.EvaluationInterval <= 0 {
		t.Fatalf("expected positive evaluation interval, got %v", cfg.EvaluationInterval)
	}
	if !cfg.DefaultAutoRollback {
		t.Fatalf("expected default auto rollback to be true")
	}
}

func TestValidateDeploymentID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid standard", "web-canary-v2", false},
		{"valid underscore dot", "api_service.v1-canary", false},
		{"empty string", "", true},
		{"spaces only", "   ", true},
		{"special characters", "canary/bad$id", true},
		{"path traversal attempt", "../canary", true},
		{"overlong id", string(make([]byte, 65)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDeploymentID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDeploymentID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestValidateWeights(t *testing.T) {
	tests := []struct {
		name     string
		baseline int
		canary   int
		wantErr  bool
	}{
		{"valid 90/10", 90, 10, false},
		{"valid 100/0", 100, 0, false},
		{"valid 0/100", 0, 100, false},
		{"valid 50/50", 50, 50, false},
		{"invalid sum", 80, 10, true},
		{"negative baseline", -10, 110, true},
		{"negative canary", 110, -10, true},
		{"over 100", 120, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWeights(tt.baseline, tt.canary)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWeights(%d, %d) error = %v, wantErr %v", tt.baseline, tt.canary, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRollbackPolicy(t *testing.T) {
	valid := RollbackPolicy{
		AutoRollback:          true,
		MaxErrorRateDelta:     5.0,
		MaxLatencyP95Ratio:    1.5,
		MinSampleSize:         20,
		ConsecutiveViolations: 2,
	}

	if err := ValidateRollbackPolicy(valid); err != nil {
		t.Fatalf("unexpected error on valid policy: %v", err)
	}

	invalidDelta := valid
	invalidDelta.MaxErrorRateDelta = 150.0
	if err := ValidateRollbackPolicy(invalidDelta); err == nil {
		t.Fatalf("expected error on invalid error delta")
	}

	invalidRatio := valid
	invalidRatio.MaxLatencyP95Ratio = 0
	if err := ValidateRollbackPolicy(invalidRatio); err == nil {
		t.Fatalf("expected error on zero latency ratio")
	}

	invalidConsecutive := valid
	invalidConsecutive.ConsecutiveViolations = 0
	if err := ValidateRollbackPolicy(invalidConsecutive); err == nil {
		t.Fatalf("expected error on zero consecutive violations")
	}
}
