package rolling

import (
	"testing"
)

func TestDefaultRollingPlanConfig(t *testing.T) {
	cfg := DefaultRollingPlanConfig()
	if cfg.BatchSize != 1 {
		t.Fatalf("expected batch size 1, got %d", cfg.BatchSize)
	}
	if cfg.DrainTimeoutSec != 5 {
		t.Fatalf("expected drain timeout 5, got %d", cfg.DrainTimeoutSec)
	}
	if cfg.ProbeTimeoutSec != 30 {
		t.Fatalf("expected probe timeout 30, got %d", cfg.ProbeTimeoutSec)
	}
	if !cfg.AutoRollback {
		t.Fatalf("expected auto rollback to be true by default")
	}
}

func TestRollingPlanConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*RollingPlanConfig)
		wantErr bool
	}{
		{
			name: "valid container IDs",
			modify: func(c *RollingPlanConfig) {
				c.TargetType = TargetContainers
				c.ContainerIDs = []string{"app-1", "app-2"}
			},
			wantErr: false,
		},
		{
			name: "empty container IDs when target_type is containers",
			modify: func(c *RollingPlanConfig) {
				c.TargetType = TargetContainers
				c.ContainerIDs = []string{}
			},
			wantErr: true,
		},
		{
			name: "valid compose stack",
			modify: func(c *RollingPlanConfig) {
				c.TargetType = TargetComposeStack
				c.TargetValue = "my-web-stack"
			},
			wantErr: false,
		},
		{
			name: "empty compose stack target value",
			modify: func(c *RollingPlanConfig) {
				c.TargetType = TargetComposeStack
				c.TargetValue = ""
			},
			wantErr: true,
		},
		{
			name: "valid label target",
			modify: func(c *RollingPlanConfig) {
				c.TargetType = TargetLabel
				c.TargetValue = "tier=backend"
			},
			wantErr: false,
		},
		{
			name: "invalid batch size exceeding 10",
			modify: func(c *RollingPlanConfig) {
				c.TargetType = TargetContainers
				c.ContainerIDs = []string{"c1"}
				c.BatchSize = 15
			},
			wantErr: true,
		},
		{
			name: "invalid drain timeout",
			modify: func(c *RollingPlanConfig) {
				c.TargetType = TargetContainers
				c.ContainerIDs = []string{"c1"}
				c.DrainTimeoutSec = 500
			},
			wantErr: true,
		},
		{
			name: "invalid probe timeout too low",
			modify: func(c *RollingPlanConfig) {
				c.TargetType = TargetContainers
				c.ContainerIDs = []string{"c1"}
				c.ProbeTimeoutSec = 1
			},
			wantErr: true,
		},
		{
			name: "invalid target type",
			modify: func(c *RollingPlanConfig) {
				c.TargetType = "unsupported"
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultRollingPlanConfig()
			tc.modify(&cfg)
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}
