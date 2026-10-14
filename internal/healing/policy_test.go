package healing

import (
	"sync"
	"testing"
)

func TestDefaultPolicyConfig(t *testing.T) {
	cfg := DefaultPolicyConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultPolicyConfig should be valid: %v", err)
	}

	if !cfg.Enabled || !cfg.AutoRestartOOM || !cfg.AutoRestartCrashLoop || !cfg.AutoRemediateUnhealthy {
		t.Errorf("Expected all healing triggers to default to true: %+v", cfg)
	}

	if cfg.MaxAttempts != 3 {
		t.Errorf("Expected default max attempts to be 3, got %d", cfg.MaxAttempts)
	}
}

func TestPolicyConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*PolicyConfig)
		wantErr bool
	}{
		{
			name:    "valid defaults",
			modify:  func(c *PolicyConfig) {},
			wantErr: false,
		},
		{
			name: "max attempts zero",
			modify: func(c *PolicyConfig) {
				c.MaxAttempts = 0
			},
			wantErr: true,
		},
		{
			name: "max attempts too high",
			modify: func(c *PolicyConfig) {
				c.MaxAttempts = 25
			},
			wantErr: true,
		},
		{
			name: "base backoff zero",
			modify: func(c *PolicyConfig) {
				c.BaseBackoffSec = 0
			},
			wantErr: true,
		},
		{
			name: "max backoff below base backoff",
			modify: func(c *PolicyConfig) {
				c.BaseBackoffSec = 30
				c.MaxBackoffSec = 10
			},
			wantErr: true,
		},
		{
			name: "jitter factor negative",
			modify: func(c *PolicyConfig) {
				c.JitterFactor = -0.1
			},
			wantErr: true,
		},
		{
			name: "jitter factor above 1",
			modify: func(c *PolicyConfig) {
				c.JitterFactor = 1.2
			},
			wantErr: true,
		},
		{
			name: "cooldown below minimum",
			modify: func(c *PolicyConfig) {
				c.CooldownSec = 5
			},
			wantErr: true,
		},
		{
			name: "invalid excluded container name",
			modify: func(c *PolicyConfig) {
				c.ExcludedContainers = []string{"valid-name", "bad name with spaces"}
			},
			wantErr: true,
		},
		{
			name: "valid excluded containers",
			modify: func(c *PolicyConfig) {
				c.ExcludedContainers = []string{"prod_db", "redis-cache", "c1234567890a"}
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultPolicyConfig()
			tc.modify(&cfg)
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestPolicyStore_ThreadSafety(t *testing.T) {
	store := NewPolicyStore(DefaultPolicyConfig())

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(iter int) {
			defer wg.Done()
			cfg := store.Get()
			if cfg.MaxAttempts < 1 {
				t.Errorf("Invalid max attempts during concurrent read: %d", cfg.MaxAttempts)
			}
		}(i)

		go func(iter int) {
			defer wg.Done()
			newCfg := DefaultPolicyConfig()
			newCfg.MaxAttempts = (iter % 5) + 1
			_ = store.Update(newCfg)
		}(i)
	}

	wg.Wait()
}
