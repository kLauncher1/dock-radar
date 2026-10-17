package federation

import (
	"strings"
	"testing"
)

func TestRegion_Validate(t *testing.T) {
	tests := []struct {
		name    string
		region  Region
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid region",
			region: Region{
				ID:        "eu-west-1",
				Name:      "EU Ireland",
				Endpoint:  "https://eu.example.com:9080",
				Latitude:  53.3498,
				Longitude: -6.2603,
				Status:    RegionStatusOnline,
			},
			wantErr: false,
		},
		{
			name: "empty id",
			region: Region{
				ID:       "",
				Name:     "EU Ireland",
				Endpoint: "https://eu.example.com",
			},
			wantErr: true,
			errMsg:  "region id cannot be empty",
		},
		{
			name: "invalid id format",
			region: Region{
				ID:       "-invalid-id-",
				Name:     "EU Ireland",
				Endpoint: "https://eu.example.com",
			},
			wantErr: true,
			errMsg:  "does not match format",
		},
		{
			name: "empty name",
			region: Region{
				ID:       "ap-south-1",
				Name:     "",
				Endpoint: "https://ap.example.com",
			},
			wantErr: true,
			errMsg:  "region name cannot be empty",
		},
		{
			name: "invalid endpoint scheme",
			region: Region{
				ID:       "ap-south-1",
				Name:     "Mumbai",
				Endpoint: "ftp://ap.example.com",
			},
			wantErr: true,
			errMsg:  "invalid region endpoint URL",
		},
		{
			name: "out of bound latitude",
			region: Region{
				ID:        "ap-south-1",
				Name:      "Mumbai",
				Endpoint:  "http://ap.example.com",
				Latitude:  95.0,
				Longitude: 72.8777,
			},
			wantErr: true,
			errMsg:  "latitude 95.00 out of bounds",
		},
		{
			name: "out of bound longitude",
			region: Region{
				ID:        "ap-south-1",
				Name:      "Mumbai",
				Endpoint:  "http://ap.example.com",
				Latitude:  19.0760,
				Longitude: 195.0,
			},
			wantErr: true,
			errMsg:  "longitude 195.00 out of bounds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.region.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q does not contain expected substring %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestFederationConfig_Validate(t *testing.T) {
	cfg := DefaultFederationConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config failed validation: %v", err)
	}

	invalidCfg := cfg
	invalidCfg.SyncIntervalSec = 2
	if err := invalidCfg.Validate(); err == nil {
		t.Fatal("expected error on sync interval < 5, got nil")
	}

	invalidCfg = cfg
	invalidCfg.ProbeTimeoutSec = 0
	if err := invalidCfg.Validate(); err == nil {
		t.Fatal("expected error on probe timeout < 1, got nil")
	}

	invalidCfg = cfg
	invalidCfg.MaxFailoverRetries = 20
	if err := invalidCfg.Validate(); err == nil {
		t.Fatal("expected error on retries > 10, got nil")
	}

	invalidCfg = cfg
	invalidCfg.TunnelKey = "   "
	if err := invalidCfg.Validate(); err == nil {
		t.Fatal("expected error on empty tunnel key, got nil")
	}
}
