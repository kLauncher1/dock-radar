package querycache

import (
	"testing"
	"time"
)

func TestDefaultConfigs(t *testing.T) {
	cacheCfg := DefaultCacheConfig()
	if err := ValidateCacheConfig(cacheCfg); err != nil {
		t.Fatalf("DefaultCacheConfig invalid: %v", err)
	}

	muxCfg := DefaultMultiplexerConfig()
	if err := ValidateMultiplexerConfig(muxCfg); err != nil {
		t.Fatalf("DefaultMultiplexerConfig invalid: %v", err)
	}

	dedupCfg := DefaultDedupConfig()
	if err := ValidateDedupConfig(dedupCfg); err != nil {
		t.Fatalf("DefaultDedupConfig invalid: %v", err)
	}
}

func TestValidateCacheConfig_Failures(t *testing.T) {
	tests := []struct {
		name string
		cfg  CacheConfig
	}{
		{
			name: "zero default TTL",
			cfg:  CacheConfig{DefaultTTL: 0, MinTTL: 1 * time.Second, MaxTTL: 5 * time.Second, MaxItems: 100, MaxMemoryBytes: 1024},
		},
		{
			name: "negative min TTL",
			cfg:  CacheConfig{DefaultTTL: 2 * time.Second, MinTTL: -1, MaxTTL: 5 * time.Second, MaxItems: 100, MaxMemoryBytes: 1024},
		},
		{
			name: "max TTL less than min TTL",
			cfg:  CacheConfig{DefaultTTL: 2 * time.Second, MinTTL: 5 * time.Second, MaxTTL: 1 * time.Second, MaxItems: 100, MaxMemoryBytes: 1024},
		},
		{
			name: "zero max items",
			cfg:  CacheConfig{DefaultTTL: 2 * time.Second, MinTTL: 500 * time.Millisecond, MaxTTL: 5 * time.Second, MaxItems: 0, MaxMemoryBytes: 1024},
		},
		{
			name: "negative max memory",
			cfg:  CacheConfig{DefaultTTL: 2 * time.Second, MinTTL: 500 * time.Millisecond, MaxTTL: 5 * time.Second, MaxItems: 100, MaxMemoryBytes: -10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateCacheConfig(tt.cfg); err == nil {
				t.Errorf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestValidateDockerEvent(t *testing.T) {
	if err := ValidateDockerEvent(nil); err == nil {
		t.Error("expected error for nil event")
	}

	emptyAction := &DockerEvent{ActorID: "c1", Action: ""}
	if err := ValidateDockerEvent(emptyAction); err == nil {
		t.Error("expected error for empty action")
	}

	noActor := &DockerEvent{Action: "start"}
	if err := ValidateDockerEvent(noActor); err == nil {
		t.Error("expected error for missing actor_id and actor_name")
	}

	valid := &DockerEvent{Action: "die", ActorID: "c1234567890"}
	if err := ValidateDockerEvent(valid); err != nil {
		t.Errorf("unexpected error for valid event: %v", err)
	}
	if valid.Type != "container" {
		t.Errorf("expected default type container, got %s", valid.Type)
	}
	if valid.Time <= 0 {
		t.Errorf("expected positive timestamp, got %d", valid.Time)
	}
}

func TestEventFilter_Matches(t *testing.T) {
	ev := DockerEvent{
		ID:        "e1",
		Type:      "container",
		Action:    "die",
		ActorID:   "c-9999",
		ActorName: "web-frontend",
	}

	if !(EventFilter{}).Matches(ev) {
		t.Error("empty filter should match all events")
	}

	if !(EventFilter{ContainerID: "c-9999"}).Matches(ev) {
		t.Error("filter with matching container ID should match")
	}

	if !(EventFilter{ContainerID: "frontend"}).Matches(ev) {
		t.Error("filter matching actor name substring should match")
	}

	if (EventFilter{ContainerID: "other-id"}).Matches(ev) {
		t.Error("mismatched container ID should not match")
	}

	if !(EventFilter{Type: "container", Action: "die"}).Matches(ev) {
		t.Error("matching type and action should match")
	}

	if (EventFilter{Action: "start"}).Matches(ev) {
		t.Error("mismatched action should not match")
	}
}
