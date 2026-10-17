package api

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/kLauncher1/dock-radar/internal/federation"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// FederationStatusResponse wraps current edge federation health and WAN sync metrics.
type FederationStatusResponse struct {
	Status      federation.FederationStatus `json:"status"`
	GeneratedAt time.Time                   `json:"generated_at"`
}

// FederationRegionsResponse provides the list of all registered edge regions.
type FederationRegionsResponse struct {
	Regions     []federation.Region `json:"regions"`
	TotalCount  int                 `json:"total_count"`
	GeneratedAt time.Time           `json:"generated_at"`
}

// FederationRoutesResponse provides current geo-distributed container routes.
type FederationRoutesResponse struct {
	Routes      []federation.ContainerRoute `json:"routes"`
	TotalCount  int                         `json:"total_count"`
	GeneratedAt time.Time                   `json:"generated_at"`
}

// FederationActionResponse conveys operation feedback.
type FederationActionResponse struct {
	Success   bool      `json:"success"`
	Action    string    `json:"action"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// FailoverRequest parses input parameters for manual traffic failovers.
type FailoverRequest struct {
	TargetID     string `json:"target_id"`
	TargetRegion string `json:"target_region"`
	Reason       string `json:"reason"`
}

// handleFederationStatus returns overall edge mesh health and WAN sync metrics.
func (h *HandlerConfig) handleFederationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.FederationEngine == nil {
		writeJSONResponse(w, http.StatusOK, FederationStatusResponse{
			Status:      federation.FederationStatus{Enabled: false, Status: federation.RegionStatusOffline},
			GeneratedAt: time.Now().UTC(),
		})
		return
	}

	writeJSONResponse(w, http.StatusOK, FederationStatusResponse{
		Status:      h.FederationEngine.GetStatus(),
		GeneratedAt: time.Now().UTC(),
	})
}

// handleFederationRegions supports listing (GET), adding (POST), and removing (DELETE) edge regions.
func (h *HandlerConfig) handleFederationRegions(w http.ResponseWriter, r *http.Request) {
	if h.FederationEngine == nil {
		http.Error(w, "federation engine disabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		status := h.FederationEngine.GetStatus()
		writeJSONResponse(w, http.StatusOK, FederationRegionsResponse{
			Regions:     status.Regions,
			TotalCount:  len(status.Regions),
			GeneratedAt: time.Now().UTC(),
		})

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		var reg federation.Region
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&reg); err != nil {
			http.Error(w, "invalid request json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.FederationEngine.RegisterRegion(&reg); err != nil {
			http.Error(w, "failed to register region: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSONResponse(w, http.StatusCreated, FederationActionResponse{
			Success:   true,
			Action:    "register_region",
			Message:   "Edge region registered successfully",
			Timestamp: time.Now().UTC(),
		})

	case http.MethodDelete:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		regionID := r.URL.Query().Get("id")
		if regionID == "" {
			var body struct {
				ID string `json:"id"`
			}
			_ = json.NewDecoder(io.LimitReader(r.Body, 4*1024)).Decode(&body)
			regionID = body.ID
		}
		if regionID == "" {
			http.Error(w, "region id required", http.StatusBadRequest)
			return
		}
		if err := h.FederationEngine.UnregisterRegion(regionID); err != nil {
			http.Error(w, "failed to unregister region: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSONResponse(w, http.StatusOK, FederationActionResponse{
			Success:   true,
			Action:    "unregister_region",
			Message:   "Edge region unregistered successfully",
			Timestamp: time.Now().UTC(),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFederationSync handles incoming encrypted WAN delta sync packets and returns response delta.
func (h *HandlerConfig) handleFederationSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.FederationEngine == nil {
		http.Error(w, "federation engine disabled", http.StatusServiceUnavailable)
		return
	}

	var packet federation.EncryptedPacket
	if err := json.NewDecoder(io.LimitReader(r.Body, 512*1024)).Decode(&packet); err != nil {
		http.Error(w, "invalid encrypted packet payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	respPacket, err := h.FederationEngine.IngestSyncPayload(&packet)
	if err != nil {
		http.Error(w, "sync payload rejection: "+err.Error(), http.StatusUnauthorized)
		return
	}

	writeJSONResponse(w, http.StatusOK, respPacket)
}

// handleFederationRoutes lists or registers geo-distributed container routes.
func (h *HandlerConfig) handleFederationRoutes(w http.ResponseWriter, r *http.Request) {
	if h.FederationEngine == nil {
		http.Error(w, "federation engine disabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		routes := h.FederationEngine.Router().ListRoutes()
		writeJSONResponse(w, http.StatusOK, FederationRoutesResponse{
			Routes:      routes,
			TotalCount:  len(routes),
			GeneratedAt: time.Now().UTC(),
		})

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		var route federation.ContainerRoute
		if err := json.NewDecoder(io.LimitReader(r.Body, 32*1024)).Decode(&route); err != nil {
			http.Error(w, "invalid route json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.FederationEngine.Router().RegisterRoute(&route); err != nil {
			http.Error(w, "failed to register route: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSONResponse(w, http.StatusCreated, FederationActionResponse{
			Success:   true,
			Action:    "register_route",
			Message:   "Container route registered successfully",
			Timestamp: time.Now().UTC(),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFederationFailover triggers manual traffic failover for a container or service.
func (h *HandlerConfig) handleFederationFailover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}
	if h.FederationEngine == nil {
		http.Error(w, "federation engine disabled", http.StatusServiceUnavailable)
		return
	}

	var req FailoverRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid request json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.TargetID == "" || req.TargetRegion == "" {
		http.Error(w, "target_id and target_region are required", http.StatusBadRequest)
		return
	}

	if err := h.FederationEngine.Router().ManualFailover(req.TargetID, req.TargetRegion, req.Reason); err != nil {
		http.Error(w, "failover failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	writeJSONResponse(w, http.StatusOK, FederationActionResponse{
		Success:   true,
		Action:    "failover",
		Message:   "Route steered to " + req.TargetRegion,
		Timestamp: time.Now().UTC(),
	})
}

// handleFederationConfig views or updates federation configuration.
func (h *HandlerConfig) handleFederationConfig(w http.ResponseWriter, r *http.Request) {
	if h.FederationEngine == nil {
		http.Error(w, "federation engine disabled", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		writeJSONResponse(w, http.StatusOK, h.FederationEngine.GetConfig())

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		var cfg federation.FederationConfig
		if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&cfg); err != nil {
			http.Error(w, "invalid config json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.FederationEngine.UpdateConfig(cfg); err != nil {
			http.Error(w, "config validation failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSONResponse(w, http.StatusOK, FederationActionResponse{
			Success:   true,
			Action:    "update_config",
			Message:   "Federation configuration updated successfully",
			Timestamp: time.Now().UTC(),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
