package federation

import (
	"math"
	"testing"
)

func TestHaversineDistance(t *testing.T) {
	// Distance between New York (40.7128, -74.0060) and London (51.5074, -0.1278) ~ 5570 km
	dist := CalculateHaversineDistance(40.7128, -74.0060, 51.5074, -0.1278)
	if math.Abs(dist-5570.0) > 50.0 {
		t.Fatalf("expected distance ~5570 km, got %.2f km", dist)
	}

	// Distance from a point to itself should be 0
	selfDist := CalculateHaversineDistance(37.7749, -122.4194, 37.7749, -122.4194)
	if selfDist > 0.001 {
		t.Fatalf("expected self-distance 0, got %.4f", selfDist)
	}
}

func TestFindNearestHealthyRegion(t *testing.T) {
	regions := []*Region{
		{ID: "us-east-1", Name: "N. Virginia", Latitude: 38.0, Longitude: -78.0, Status: RegionStatusOnline},
		{ID: "eu-west-1", Name: "Ireland", Latitude: 53.0, Longitude: -8.0, Status: RegionStatusOnline},
		{ID: "ap-northeast-1", Name: "Tokyo", Latitude: 35.6, Longitude: 139.6, Status: RegionStatusOffline},
	}

	// Query from Paris (48.8, 2.3) -> Nearest should be Ireland
	nearest, dist, err := FindNearestHealthyRegion(48.8, 2.3, regions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nearest.ID != "eu-west-1" {
		t.Fatalf("expected nearest region eu-west-1, got %s (dist: %.2f km)", nearest.ID, dist)
	}

	// Query from Seoul (37.5, 127.0) -> Tokyo is offline, so next closest online is us-east-1 or eu-west-1
	nearest2, _, err := FindNearestHealthyRegion(37.5, 127.0, regions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nearest2.ID == "ap-northeast-1" {
		t.Fatalf("expected offline region to be skipped, but got %s", nearest2.ID)
	}
}

func TestGeoRouter_AutomatedFailoverAndRecovery(t *testing.T) {
	router := NewGeoRouter()

	route := &ContainerRoute{
		TargetID:        "auth-service",
		ServiceName:     "Authentication Service",
		Policy:          PolicyPrimaryBackup,
		PrimaryRegion:   "us-east-1",
		FallbackRegions: []string{"eu-central-1", "ap-southeast-1"},
	}
	if err := router.RegisterRoute(route); err != nil {
		t.Fatalf("register route failed: %v", err)
	}

	regions := map[string]*Region{
		"us-east-1":      {ID: "us-east-1", Status: RegionStatusOnline, ConsecutiveFailures: 0},
		"eu-central-1":   {ID: "eu-central-1", Status: RegionStatusOnline, ConsecutiveFailures: 0},
		"ap-southeast-1": {ID: "ap-southeast-1", Status: RegionStatusOnline, ConsecutiveFailures: 0},
	}

	// 1. Initial healthy evaluation -> No failovers
	events := router.EvaluateFailovers(regions, true, 3)
	if len(events) != 0 {
		t.Fatalf("expected 0 failovers when healthy, got %d", len(events))
	}

	// 2. Degrade primary region -> Trigger failover to eu-central-1
	regions["us-east-1"].Status = RegionStatusOffline
	regions["us-east-1"].ConsecutiveFailures = 3
	events = router.EvaluateFailovers(regions, true, 3)
	if len(events) != 1 {
		t.Fatalf("expected 1 failover event, got %d", len(events))
	}
	if events[0].ToRegion != "eu-central-1" {
		t.Fatalf("expected failover to eu-central-1, got %s", events[0].ToRegion)
	}

	r, ok := router.GetRoute("auth-service")
	if !ok || !r.FailoverActive || r.ActiveRegion != "eu-central-1" {
		t.Fatalf("unexpected route state after failover: %+v", r)
	}

	// 3. Primary recovers -> Trigger automatic failback
	regions["us-east-1"].Status = RegionStatusOnline
	regions["us-east-1"].ConsecutiveFailures = 0
	recoveryEvents := router.EvaluateFailovers(regions, true, 3)
	if len(recoveryEvents) != 1 {
		t.Fatalf("expected 1 recovery failback event, got %d", len(recoveryEvents))
	}
	if recoveryEvents[0].ToRegion != "us-east-1" {
		t.Fatalf("expected failback to us-east-1, got %s", recoveryEvents[0].ToRegion)
	}

	r, _ = router.GetRoute("auth-service")
	if r.FailoverActive || r.ActiveRegion != "us-east-1" {
		t.Fatalf("expected normal primary route after recovery, got %+v", r)
	}
}

func TestGeoRouter_ManualFailover(t *testing.T) {
	router := NewGeoRouter()
	_ = router.RegisterRoute(&ContainerRoute{
		TargetID:      "database-replica",
		PrimaryRegion: "us-west-2",
	})

	if err := router.ManualFailover("database-replica", "sa-east-1", "Scheduled maintenance"); err != nil {
		t.Fatalf("manual failover failed: %v", err)
	}

	r, ok := router.GetRoute("database-replica")
	if !ok || r.ActiveRegion != "sa-east-1" || !r.FailoverActive {
		t.Fatalf("unexpected state after manual failover: %+v", r)
	}

	events := router.RecentEvents()
	if len(events) != 1 || router.FailoverEventsCount() != 1 {
		t.Fatalf("expected 1 recorded failover event, got %d count=%d", len(events), router.FailoverEventsCount())
	}
}
