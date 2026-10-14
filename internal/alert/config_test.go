package alert

import (
	"errors"
	"sync"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Errorf("expected default Enabled to be false")
	}
	if cfg.CPUThresholdPercent != 85.0 {
		t.Errorf("expected CPUThresholdPercent 85.0, got %f", cfg.CPUThresholdPercent)
	}
	if cfg.MemoryThresholdMB != 500.0 {
		t.Errorf("expected MemoryThresholdMB 500.0, got %f", cfg.MemoryThresholdMB)
	}
	if cfg.RestartThresholdCount != 3 {
		t.Errorf("expected RestartThresholdCount 3, got %d", cfg.RestartThresholdCount)
	}
	if cfg.FlappingWindowSeconds != 300 {
		t.Errorf("expected FlappingWindowSeconds 300, got %d", cfg.FlappingWindowSeconds)
	}
	if cfg.CooldownSeconds != 60 {
		t.Errorf("expected CooldownSeconds 60, got %d", cfg.CooldownSeconds)
	}
}

func TestConfigStore_UpdateAndGet(t *testing.T) {
	store := NewConfigStore(DefaultConfig())

	newCfg := Config{
		Enabled:               true,
		DiscordWebhookURL:     "https://discord.com/api/webhooks/12345/abcdef",
		SlackWebhookURL:       "https://hooks.slack.com/services/T00/B00/X00",
		CPUThresholdPercent:   90.0,
		MemoryThresholdMB:     1024.0,
		RestartThresholdCount: 5,
		FlappingWindowSeconds: 600,
		CooldownSeconds:       120,
	}

	if err := store.Update(newCfg); err != nil {
		t.Fatalf("unexpected update error: %v", err)
	}

	got := store.Get()
	if !got.Enabled {
		t.Errorf("expected Enabled to be true")
	}
	if got.DiscordWebhookURL != newCfg.DiscordWebhookURL {
		t.Errorf("expected discord url %q, got %q", newCfg.DiscordWebhookURL, got.DiscordWebhookURL)
	}
	if got.CPUThresholdPercent != 90.0 {
		t.Errorf("expected CPUThresholdPercent 90.0, got %f", got.CPUThresholdPercent)
	}
}

func TestConfigStore_UpdateValidationFailures(t *testing.T) {
	store := NewConfigStore(DefaultConfig())

	// Test invalid URL
	badURLCfg := DefaultConfig()
	badURLCfg.DiscordWebhookURL = "ftp://malicious.org/hook"
	if err := store.Update(badURLCfg); err == nil {
		t.Fatalf("expected error for ftp scheme, got nil")
	}

	// Test invalid CPU threshold
	badCPUCfg := DefaultConfig()
	badCPUCfg.CPUThresholdPercent = 150.0
	if err := store.Update(badCPUCfg); err == nil {
		t.Fatalf("expected error for CPU threshold > 100, got nil")
	}

	// Test invalid Memory threshold
	badMemCfg := DefaultConfig()
	badMemCfg.MemoryThresholdMB = -10.0
	if err := store.Update(badMemCfg); err == nil {
		t.Fatalf("expected error for negative memory threshold, got nil")
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name      string
		rawURL    string
		shouldErr bool
		errTarget error
	}{
		{
			name:      "valid https discord webhook",
			rawURL:    "https://discord.com/api/webhooks/123/xyz",
			shouldErr: false,
		},
		{
			name:      "valid https slack webhook",
			rawURL:    "https://hooks.slack.com/services/T01/B02/XYZ",
			shouldErr: false,
		},
		{
			name:      "valid local test server",
			rawURL:    "http://127.0.0.1:9090/webhook",
			shouldErr: false,
		},
		{
			name:      "empty URL",
			rawURL:    "",
			shouldErr: true,
			errTarget: ErrEmptyURL,
		},
		{
			name:      "whitespace only",
			rawURL:    "   ",
			shouldErr: true,
			errTarget: ErrEmptyURL,
		},
		{
			name:      "file scheme",
			rawURL:    "file:///etc/passwd",
			shouldErr: true,
			errTarget: ErrInvalidScheme,
		},
		{
			name:      "gopher scheme",
			rawURL:    "gopher://127.0.0.1:70",
			shouldErr: true,
			errTarget: ErrInvalidScheme,
		},
		{
			name:      "CRLF injection attempt",
			rawURL:    "https://discord.com/api/webhooks\r\nHost: evil.com",
			shouldErr: true,
		},
		{
			name:      "null byte injection attempt",
			rawURL:    "https://discord.com/api/webhooks\x00extra",
			shouldErr: true,
		},
		{
			name:      "AWS metadata SSRF",
			rawURL:    "http://169.254.169.254/latest/meta-data/",
			shouldErr: true,
			errTarget: ErrSSRFBlocked,
		},
		{
			name:      "Google cloud metadata SSRF",
			rawURL:    "http://metadata.google.internal/computeMetadata/v1/",
			shouldErr: true,
			errTarget: ErrSSRFBlocked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURL(tt.rawURL)
			if tt.shouldErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tt.rawURL)
				}
				if tt.errTarget != nil && !errors.Is(err, tt.errTarget) {
					t.Fatalf("expected error type %v, got %v", tt.errTarget, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %q: %v", tt.rawURL, err)
				}
			}
		})
	}
}

func TestConfigStore_Concurrency(t *testing.T) {
	store := NewConfigStore(DefaultConfig())
	var wg sync.WaitGroup

	for i := 0; i < 30; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			_ = store.Get()
		}(i)

		go func(idx int) {
			defer wg.Done()
			cfg := DefaultConfig()
			cfg.CPUThresholdPercent = float64(50 + (idx % 40))
			_ = store.Update(cfg)
		}(i)
	}

	wg.Wait()
	final := store.Get()
	if final.CPUThresholdPercent < 50 || final.CPUThresholdPercent > 90 {
		t.Errorf("unexpected final CPUThresholdPercent: %f", final.CPUThresholdPercent)
	}
}
