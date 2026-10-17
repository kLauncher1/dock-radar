package federation

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// RegionStatus denotes the operational health of an edge region node.
type RegionStatus string

const (
	RegionStatusOnline      RegionStatus = "online"
	RegionStatusDegraded    RegionStatus = "degraded"
	RegionStatusOffline     RegionStatus = "offline"
	RegionStatusUnreachable RegionStatus = "unreachable"
)

var regionIDRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9\-_]{1,48}[a-z0-9]$`)

// Region encapsulates geographic and connectivity metadata for a federated edge cluster.
type Region struct {
	ID                  string       `json:"id"`
	Name                string       `json:"name"`
	Endpoint            string       `json:"endpoint"`
	Latitude            float64      `json:"latitude"`
	Longitude           float64      `json:"longitude"`
	Status              RegionStatus `json:"status"`
	PingRTTMs           int64        `json:"ping_rtt_ms"`
	ContainerCount      int          `json:"container_count"`
	LastSyncTime        time.Time    `json:"last_sync_time"`
	ConsecutiveFailures int          `json:"consecutive_failures,omitempty"`
}

// Validate checks integrity, bounds, and schema validity of a Region.
func (r *Region) Validate() error {
	if r.ID == "" {
		return errors.New("region id cannot be empty")
	}
	if !regionIDRegex.MatchString(r.ID) {
		return fmt.Errorf("region id %q does not match format [a-z0-9-_] (length 3-50)", r.ID)
	}
	if r.Name == "" {
		return errors.New("region name cannot be empty")
	}
	if len(r.Name) > 64 {
		return errors.New("region name cannot exceed 64 characters")
	}
	if r.Endpoint == "" {
		return errors.New("region endpoint cannot be empty")
	}
	parsedURL, err := url.Parse(r.Endpoint)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return fmt.Errorf("invalid region endpoint URL: %q", r.Endpoint)
	}
	if r.Latitude < -90.0 || r.Latitude > 90.0 {
		return fmt.Errorf("latitude %.2f out of bounds [-90, 90]", r.Latitude)
	}
	if r.Longitude < -180.0 || r.Longitude > 180.0 {
		return fmt.Errorf("longitude %.2f out of bounds [-180, 180]", r.Longitude)
	}
	return nil
}

// FederationConfig defines runtime parameters for multi-region peer federation.
type FederationConfig struct {
	Enabled             bool   `json:"enabled"`
	LocalRegionID       string `json:"local_region_id"`
	LocalRegionName     string `json:"local_region_name"`
	SyncIntervalSec     int    `json:"sync_interval_sec"`
	ProbeTimeoutSec     int    `json:"probe_timeout_sec"`
	MaxFailoverRetries  int    `json:"max_failover_retries"`
	AutoFailoverEnabled bool   `json:"auto_failover_enabled"`
	TunnelKey           string `json:"-"`
}

// DefaultFederationConfig returns secure production default parameters.
func DefaultFederationConfig() FederationConfig {
	return FederationConfig{
		Enabled:             true,
		LocalRegionID:       "us-east-1",
		LocalRegionName:     "US East (N. Virginia)",
		SyncIntervalSec:     30,
		ProbeTimeoutSec:     5,
		MaxFailoverRetries:  3,
		AutoFailoverEnabled: true,
		TunnelKey:           "dock-radar-federation-default-key-32b",
	}
}

// Validate verifies config boundaries and prevents misconfigurations.
func (c *FederationConfig) Validate() error {
	if c.LocalRegionID == "" {
		return errors.New("local_region_id is required")
	}
	if !regionIDRegex.MatchString(c.LocalRegionID) {
		return fmt.Errorf("invalid local_region_id %q", c.LocalRegionID)
	}
	if c.SyncIntervalSec < 5 || c.SyncIntervalSec > 3600 {
		return errors.New("sync_interval_sec must be between 5 and 3600")
	}
	if c.ProbeTimeoutSec < 1 || c.ProbeTimeoutSec > 60 {
		return errors.New("probe_timeout_sec must be between 1 and 60")
	}
	if c.MaxFailoverRetries < 1 || c.MaxFailoverRetries > 10 {
		return errors.New("max_failover_retries must be between 1 and 10")
	}
	if strings.TrimSpace(c.TunnelKey) == "" {
		return errors.New("tunnel key cannot be empty")
	}
	return nil
}

// FederationStatus aggregates edge federation health and WAN synchronization metrics.
type FederationStatus struct {
	Enabled                bool         `json:"enabled"`
	LocalRegionID          string       `json:"local_region_id"`
	LocalRegionName        string       `json:"local_region_name"`
	TotalRegions           int          `json:"total_regions"`
	HealthyRegions         int          `json:"healthy_regions"`
	ActiveTunnels          int          `json:"active_tunnels"`
	TotalSyncBytes         int64        `json:"total_sync_bytes"`
	TotalSavedBytes        int64        `json:"total_saved_bytes"`
	DeltaEfficiencyPercent float64      `json:"delta_efficiency_percent"`
	FailoverCount          int64        `json:"failover_count"`
	LastSyncTime           time.Time    `json:"last_sync_time"`
	Regions                []Region     `json:"regions"`
	Status                 RegionStatus `json:"status"`
}
