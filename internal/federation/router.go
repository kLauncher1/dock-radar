package federation

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// RoutePolicy determines the traffic distribution strategy across regions.
type RoutePolicy string

const (
	PolicyLowestLatency RoutePolicy = "lowest_latency"
	PolicyGeoProximity  RoutePolicy = "geo_proximity"
	PolicyPrimaryBackup RoutePolicy = "primary_backup"
)

// ContainerRoute manages the routing target and failover state for a container or service.
type ContainerRoute struct {
	TargetID        string      `json:"target_id"`
	ServiceName     string      `json:"service_name"`
	Policy          RoutePolicy `json:"policy"`
	PrimaryRegion   string      `json:"primary_region"`
	FallbackRegions []string    `json:"fallback_regions"`
	ActiveRegion    string      `json:"active_region"`
	FailoverActive  bool        `json:"failover_active"`
	FailoverReason  string      `json:"failover_reason,omitempty"`
	LastEvaluated   time.Time   `json:"last_evaluated"`
}

// FailoverEvent records when a route is steered to an alternate edge region.
type FailoverEvent struct {
	TargetID    string    `json:"target_id"`
	ServiceName string    `json:"service_name"`
	FromRegion  string    `json:"from_region"`
	ToRegion    string    `json:"to_region"`
	Reason      string    `json:"reason"`
	Timestamp   time.Time `json:"timestamp"`
}

// GeoRouter orchestrates geo-distributed inventory routing and dynamic failovers.
type GeoRouter struct {
	mu            sync.RWMutex
	routes        map[string]*ContainerRoute
	failoverCount int64
	history       []FailoverEvent
	maxHistory    int
}

// NewGeoRouter initializes a geo-distributed container inventory router.
func NewGeoRouter() *GeoRouter {
	return &GeoRouter{
		routes:     make(map[string]*ContainerRoute),
		maxHistory: 100,
	}
}

// RegisterRoute adds or updates a container routing rule.
func (r *GeoRouter) RegisterRoute(route *ContainerRoute) error {
	if route == nil || route.TargetID == "" {
		return errors.New("invalid route target id")
	}
	if route.PrimaryRegion == "" {
		return errors.New("primary region is required")
	}
	if route.ActiveRegion == "" {
		route.ActiveRegion = route.PrimaryRegion
	}
	if route.Policy == "" {
		route.Policy = PolicyPrimaryBackup
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	route.LastEvaluated = time.Now().UTC()
	r.routes[route.TargetID] = route
	return nil
}

// GetRoute returns the active route for a container or service.
func (r *GeoRouter) GetRoute(targetID string) (*ContainerRoute, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	route, exists := r.routes[targetID]
	if !exists {
		return nil, false
	}
	copied := *route
	return &copied, true
}

// ListRoutes returns a snapshot of all registered routes.
func (r *GeoRouter) ListRoutes() []ContainerRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]ContainerRoute, 0, len(r.routes))
	for _, route := range r.routes {
		result = append(result, *route)
	}
	return result
}

// EvaluateFailovers assesses region health and dynamically redirects traffic if needed.
func (r *GeoRouter) EvaluateFailovers(regions map[string]*Region, autoFailover bool, maxFailures int) []FailoverEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	events := make([]FailoverEvent, 0)
	now := time.Now().UTC()

	for _, route := range r.routes {
		route.LastEvaluated = now
		primaryReg, primaryExists := regions[route.PrimaryRegion]
		primaryHealthy := primaryExists && primaryReg.Status == RegionStatusOnline && primaryReg.ConsecutiveFailures < maxFailures

		if route.FailoverActive {
			// Check recovery probation: restore to primary if healthy again
			if primaryHealthy {
				event := FailoverEvent{
					TargetID:    route.TargetID,
					ServiceName: route.ServiceName,
					FromRegion:  route.ActiveRegion,
					ToRegion:    route.PrimaryRegion,
					Reason:      "Primary region recovered to online status",
					Timestamp:   now,
				}
				route.ActiveRegion = route.PrimaryRegion
				route.FailoverActive = false
				route.FailoverReason = ""
				events = append(events, event)
				r.recordEvent(event)
			}
			continue
		}

		// Trigger failover if primary region is degraded or offline
		if !primaryHealthy && autoFailover {
			// Find first healthy fallback region
			var targetFallback string
			for _, fb := range route.FallbackRegions {
				if fbReg, fbExists := regions[fb]; fbExists && fbReg.Status == RegionStatusOnline {
					targetFallback = fb
					break
				}
			}

			if targetFallback != "" {
				reason := fmt.Sprintf("Primary region %s is offline/unreachable", route.PrimaryRegion)
				if primaryExists && primaryReg.ConsecutiveFailures >= maxFailures {
					reason = fmt.Sprintf("Primary region %s exceeded failure threshold (%d attempts)", route.PrimaryRegion, primaryReg.ConsecutiveFailures)
				}

				event := FailoverEvent{
					TargetID:    route.TargetID,
					ServiceName: route.ServiceName,
					FromRegion:  route.PrimaryRegion,
					ToRegion:    targetFallback,
					Reason:      reason,
					Timestamp:   now,
				}
				route.ActiveRegion = targetFallback
				route.FailoverActive = true
				route.FailoverReason = reason
				events = append(events, event)
				atomic.AddInt64(&r.failoverCount, 1)
				r.recordEvent(event)
			}
		}
	}

	return events
}

// ManualFailover overrides active routing destination for administrative failover testing.
func (r *GeoRouter) ManualFailover(targetID, targetRegion, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[targetID]
	if !exists {
		return fmt.Errorf("route %q not found", targetID)
	}

	event := FailoverEvent{
		TargetID:    route.TargetID,
		ServiceName: route.ServiceName,
		FromRegion:  route.ActiveRegion,
		ToRegion:    targetRegion,
		Reason:      "Manual failover: " + reason,
		Timestamp:   time.Now().UTC(),
	}
	route.ActiveRegion = targetRegion
	route.FailoverActive = (targetRegion != route.PrimaryRegion)
	route.FailoverReason = event.Reason
	route.LastEvaluated = time.Now().UTC()
	atomic.AddInt64(&r.failoverCount, 1)
	r.recordEvent(event)

	return nil
}

func (r *GeoRouter) recordEvent(ev FailoverEvent) {
	r.history = append(r.history, ev)
	if len(r.history) > r.maxHistory {
		r.history = r.history[len(r.history)-r.maxHistory:]
	}
}

// RecentEvents returns recent failover occurrences.
func (r *GeoRouter) RecentEvents() []FailoverEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]FailoverEvent, len(r.history))
	copy(result, r.history)
	return result
}

// FailoverEventsCount returns total lifetime failover activations.
func (r *GeoRouter) FailoverEventsCount() int64 {
	return atomic.LoadInt64(&r.failoverCount)
}

// CalculateHaversineDistance returns great-circle distance in kilometers between two geo coordinates.
func CalculateHaversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKm = 6371.0

	radLat1 := lat1 * math.Pi / 180.0
	radLat2 := lat2 * math.Pi / 180.0
	deltaLat := (lat2 - lat1) * math.Pi / 180.0
	deltaLon := (lon2 - lon1) * math.Pi / 180.0

	a := math.Sin(deltaLat/2.0)*math.Sin(deltaLat/2.0) +
		math.Cos(radLat1)*math.Cos(radLat2)*
			math.Sin(deltaLon/2.0)*math.Sin(deltaLon/2.0)

	c := 2.0 * math.Atan2(math.Sqrt(a), math.Sqrt(1.0-a))
	return earthRadiusKm * c
}

// FindNearestHealthyRegion identifies the closest online region to a client location.
func FindNearestHealthyRegion(clientLat, clientLon float64, regions []*Region) (*Region, float64, error) {
	if len(regions) == 0 {
		return nil, 0, errors.New("no regions provided")
	}

	var bestRegion *Region
	minDist := math.MaxFloat64

	for _, reg := range regions {
		if reg.Status != RegionStatusOnline {
			continue
		}
		dist := CalculateHaversineDistance(clientLat, clientLon, reg.Latitude, reg.Longitude)
		if dist < minDist {
			minDist = dist
			bestRegion = reg
		}
	}

	if bestRegion == nil {
		return nil, 0, errors.New("no healthy online regions available")
	}
	return bestRegion, minDist, nil
}
