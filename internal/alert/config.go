package alert

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

var (
	// ErrEmptyURL indicates an empty URL was provided where a URL was required.
	ErrEmptyURL = errors.New("url cannot be empty")
	// ErrInvalidScheme indicates an unsupported protocol was provided.
	ErrInvalidScheme = errors.New("only http and https URL schemes are allowed")
	// ErrSSRFBlocked indicates an attempted request to cloud metadata or dangerous endpoint.
	ErrSSRFBlocked = errors.New("url target blocked by security policy")
)

// Config represents alerting and webhook threshold parameters.
type Config struct {
	Enabled               bool    `json:"enabled"`
	DiscordWebhookURL     string  `json:"discord_webhook_url"`
	SlackWebhookURL       string  `json:"slack_webhook_url"`
	CPUThresholdPercent   float64 `json:"cpu_threshold_percent"`
	MemoryThresholdMB     float64 `json:"memory_threshold_mb"`
	RestartThresholdCount int     `json:"restart_threshold_count"`
	FlappingWindowSeconds int     `json:"flapping_window_seconds"`
	CooldownSeconds       int     `json:"cooldown_seconds"`
}

// DefaultConfig provides sensible production defaults for alert monitoring.
func DefaultConfig() Config {
	return Config{
		Enabled:               false,
		DiscordWebhookURL:     "",
		SlackWebhookURL:       "",
		CPUThresholdPercent:   85.0,
		MemoryThresholdMB:     500.0,
		RestartThresholdCount: 3,
		FlappingWindowSeconds: 300,
		CooldownSeconds:       60,
	}
}

// ConfigStore maintains thread-safe read/write access to alert configuration.
type ConfigStore struct {
	mu  sync.RWMutex
	cfg Config
}

// NewConfigStore creates a new thread-safe configuration repository with normalized defaults.
func NewConfigStore(initial Config) *ConfigStore {
	defaults := DefaultConfig()
	if initial.CPUThresholdPercent <= 0 || initial.CPUThresholdPercent > 100 {
		initial.CPUThresholdPercent = defaults.CPUThresholdPercent
	}
	if initial.MemoryThresholdMB <= 0 {
		initial.MemoryThresholdMB = defaults.MemoryThresholdMB
	}
	if initial.RestartThresholdCount <= 0 {
		initial.RestartThresholdCount = defaults.RestartThresholdCount
	}
	if initial.FlappingWindowSeconds <= 0 {
		initial.FlappingWindowSeconds = defaults.FlappingWindowSeconds
	}
	if initial.CooldownSeconds <= 0 {
		initial.CooldownSeconds = defaults.CooldownSeconds
	}

	return &ConfigStore{
		cfg: initial,
	}
}

// Get safely returns a snapshot copy of the current alert configuration.
func (s *ConfigStore) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Update validates parameters and updates the stored configuration thread-safely.
func (s *ConfigStore) Update(newCfg Config) error {
	trimmedDiscord := strings.TrimSpace(newCfg.DiscordWebhookURL)
	if trimmedDiscord != "" {
		if err := ValidateURL(trimmedDiscord); err != nil {
			return fmt.Errorf("invalid discord webhook url: %w", err)
		}
	}
	newCfg.DiscordWebhookURL = trimmedDiscord

	trimmedSlack := strings.TrimSpace(newCfg.SlackWebhookURL)
	if trimmedSlack != "" {
		if err := ValidateURL(trimmedSlack); err != nil {
			return fmt.Errorf("invalid slack webhook url: %w", err)
		}
	}
	newCfg.SlackWebhookURL = trimmedSlack

	if newCfg.CPUThresholdPercent <= 0 || newCfg.CPUThresholdPercent > 100 {
		return fmt.Errorf("cpu_threshold_percent must be between 1 and 100")
	}
	if newCfg.MemoryThresholdMB <= 0 {
		return fmt.Errorf("memory_threshold_mb must be greater than 0")
	}
	if newCfg.RestartThresholdCount <= 0 {
		return fmt.Errorf("restart_threshold_count must be at least 1")
	}
	if newCfg.FlappingWindowSeconds <= 0 {
		return fmt.Errorf("flapping_window_seconds must be at least 1")
	}
	if newCfg.CooldownSeconds <= 0 {
		return fmt.Errorf("cooldown_seconds must be at least 1")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = newCfg
	return nil
}

// ValidateURL checks URL format, schemes, control character injection, and SSRF attack vectors.
func ValidateURL(urlStr string) error {
	trimmed := strings.TrimSpace(urlStr)
	if trimmed == "" {
		return ErrEmptyURL
	}

	// Reject CRLF, control characters, tabs, and spaces inside URL string
	for _, ch := range trimmed {
		if ch < 32 || ch == 127 {
			return fmt.Errorf("url contains illegal control characters")
		}
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("failed to parse url: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return ErrInvalidScheme
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return fmt.Errorf("url missing valid host")
	}

	// SSRF protection: block known cloud metadata endpoints
	lowerHost := strings.ToLower(host)
	blockedHosts := []string{
		"169.254.169.254",
		"169.254.169.253",
		"metadata.google.internal",
		"metadata.internal",
		"instance-data",
	}

	for _, blocked := range blockedHosts {
		if lowerHost == blocked || strings.HasSuffix(lowerHost, "."+blocked) {
			return fmt.Errorf("%w: target %s is prohibited", ErrSSRFBlocked, lowerHost)
		}
	}

	return nil
}
