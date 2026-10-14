package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/kLauncher1/dock-radar/internal/anomaly"
	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// AnomalyPredictionsResponse encapsulates current regression forecasts and radar summary.
type AnomalyPredictionsResponse struct {
	Summary     anomaly.AnomalySummary    `json:"summary"`
	Predictions []anomaly.TrendPrediction `json:"predictions"`
	GeneratedAt time.Time                 `json:"generated_at"`
}

// AnomalyEventsResponse provides recent early-warning alert incidents.
type AnomalyEventsResponse struct {
	Events     []anomaly.AlarmEvent `json:"events"`
	TotalCount int                  `json:"total_count"`
	CheckedAt  time.Time            `json:"checked_at"`
}

// handleAnomalyPredictions returns real-time linear regression OOM predictions across containers.
func (h *HandlerConfig) handleAnomalyPredictions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.AnomalyDetector == nil {
		writeJSONResponse(w, http.StatusOK, AnomalyPredictionsResponse{
			Summary:     anomaly.AnomalySummary{CheckedAt: time.Now().UTC()},
			Predictions: []anomaly.TrendPrediction{},
			GeneratedAt: time.Now().UTC(),
		})
		return
	}

	all := h.AnomalyDetector.GetPredictions()
	summary := h.AnomalyDetector.GetSummary()

	filter := r.URL.Query().Get("filter")
	targetID := r.URL.Query().Get("id")

	var filtered []anomaly.TrendPrediction
	for _, p := range all {
		if targetID != "" && p.ContainerID != targetID && p.ContainerName != targetID {
			continue
		}
		if filter == "at_risk" {
			if p.Category != anomaly.ExhaustionCritical && p.Category != anomaly.ExhaustionWarning && p.Category != anomaly.ExhaustionModerate {
				continue
			}
		}
		filtered = append(filtered, p)
	}

	writeJSONResponse(w, http.StatusOK, AnomalyPredictionsResponse{
		Summary:     summary,
		Predictions: filtered,
		GeneratedAt: time.Now().UTC(),
	})
}

// handleAnomalyConfig handles reading and updating early-warning alarm configurations.
func (h *HandlerConfig) handleAnomalyConfig(w http.ResponseWriter, r *http.Request) {
	if h.AnomalyDetector == nil {
		http.Error(w, "anomaly detector not initialized", http.StatusServiceUnavailable)
		return
	}
	alarms := h.AnomalyDetector.Alarms()

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		cfg := alarms.GetConfig()
		writeJSONResponse(w, http.StatusOK, cfg)

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024))
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}

		var newCfg anomaly.AlarmConfig
		if err := json.Unmarshal(body, &newCfg); err != nil {
			http.Error(w, "invalid json payload: "+err.Error(), http.StatusBadRequest)
			return
		}

		if err := alarms.UpdateConfig(newCfg); err != nil {
			http.Error(w, "invalid configuration: "+err.Error(), http.StatusBadRequest)
			return
		}

		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Action: "update_anomaly_config",
				Target: "anomaly_detector",
				Details: map[string]any{
					"enabled":            newCfg.Enabled,
					"warning_horizon_s":  newCfg.WarningHorizonSeconds,
					"critical_horizon_s": newCfg.CriticalHorizonSeconds,
					"dispatch_webhooks":  newCfg.DispatchWebhooks,
				},
			})
		}

		writeJSONResponse(w, http.StatusOK, alarms.GetConfig())

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAnomalyEvents queries recent early warning OOM incidents.
func (h *HandlerConfig) handleAnomalyEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.AnomalyDetector == nil {
		writeJSONResponse(w, http.StatusOK, AnomalyEventsResponse{
			Events:    []anomaly.AlarmEvent{},
			CheckedAt: time.Now().UTC(),
		})
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if parsed, err := strconv.Atoi(lStr); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}

	events := h.AnomalyDetector.Alarms().RecentEvents(limit)
	writeJSONResponse(w, http.StatusOK, AnomalyEventsResponse{
		Events:     events,
		TotalCount: len(events),
		CheckedAt:  time.Now().UTC(),
	})
}
