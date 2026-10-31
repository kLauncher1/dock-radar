package api

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/kLauncher1/dock-radar/internal/canary"
	"github.com/kLauncher1/dock-radar/internal/security"
)

type canaryWeightRequest struct {
	ID           string `json:"id"`
	CanaryWeight int    `json:"canary_weight"`
}

type canaryActionRequest struct {
	ID     string `json:"id"`
	Reason string `json:"reason,omitempty"`
}

type canaryRouteRequest struct {
	ID        string            `json:"id"`
	RequestID string            `json:"request_id"`
	Headers   map[string]string `json:"headers,omitempty"`
}

type canarySampleRequest struct {
	ID         string  `json:"id"`
	Target     string  `json:"target"` // "baseline", "canary", "shadow"
	StatusCode int     `json:"status_code"`
	DurationMs float64 `json:"duration_ms"`
}

type canaryDetailResponse struct {
	Deployment *canary.CanaryDeployment       `json:"deployment"`
	Report     *canary.CanaryDivergenceReport `json:"report,omitempty"`
}

func (cfg *HandlerConfig) handleCanaryStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.CanaryEngine == nil {
		http.Error(w, "Canary engine not configured", http.StatusServiceUnavailable)
		return
	}

	status := cfg.CanaryEngine.Status()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(status)
}

func (cfg *HandlerConfig) handleCanaryDeployments(w http.ResponseWriter, r *http.Request) {
	if cfg.CanaryEngine == nil {
		http.Error(w, "Canary engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !cfg.authorize(w, r, security.RoleViewer) {
			return
		}
		deployments := cfg.CanaryEngine.ListDeployments()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(deployments)

	case http.MethodPost:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		var dep canary.CanaryDeployment
		if err := json.Unmarshal(body, &dep); err != nil {
			http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}

		created, err := cfg.CanaryEngine.CreateDeployment(dep)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(created)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cfg *HandlerConfig) handleCanaryDeploymentDetail(w http.ResponseWriter, r *http.Request) {
	if cfg.CanaryEngine == nil {
		http.Error(w, "Canary engine not configured", http.StatusServiceUnavailable)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !cfg.authorize(w, r, security.RoleViewer) {
			return
		}
		dep, err := cfg.CanaryEngine.GetDeployment(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		report, _ := cfg.CanaryEngine.GetDivergenceReport(id)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(canaryDetailResponse{
			Deployment: dep,
			Report:     report,
		})

	case http.MethodDelete:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		if err := cfg.CanaryEngine.DeleteDeployment(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cfg *HandlerConfig) handleCanaryWeight(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.CanaryEngine == nil {
		http.Error(w, "Canary engine not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var req canaryWeightRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := cfg.CanaryEngine.UpdateWeight(req.ID, req.CanaryWeight); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	dep, _ := cfg.CanaryEngine.GetDeployment(req.ID)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(dep)
}

func (cfg *HandlerConfig) handleCanaryPromote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.CanaryEngine == nil {
		http.Error(w, "Canary engine not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var req canaryActionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := cfg.CanaryEngine.Promote(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	dep, _ := cfg.CanaryEngine.GetDeployment(req.ID)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(dep)
}

func (cfg *HandlerConfig) handleCanaryRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.CanaryEngine == nil {
		http.Error(w, "Canary engine not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var req canaryActionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "manual operator rollback via api"
	}

	if err := cfg.CanaryEngine.Rollback(req.ID, reason); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	dep, _ := cfg.CanaryEngine.GetDeployment(req.ID)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(dep)
}

func (cfg *HandlerConfig) handleCanaryRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.CanaryEngine == nil {
		http.Error(w, "Canary engine not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var req canaryRouteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	decision, err := cfg.CanaryEngine.RouteTraffic(req.ID, req.RequestID, req.Headers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(decision)
}

func (cfg *HandlerConfig) handleCanarySample(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.CanaryEngine == nil {
		http.Error(w, "Canary engine not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var req canarySampleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	duration := time.Duration(req.DurationMs * float64(time.Millisecond))
	if err := cfg.CanaryEngine.RecordSample(req.ID, req.Target, req.StatusCode, duration); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "recorded"})
}

func (cfg *HandlerConfig) handleCanaryConfig(w http.ResponseWriter, r *http.Request) {
	if cfg.CanaryEngine == nil {
		http.Error(w, "Canary engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !cfg.authorize(w, r, security.RoleViewer) {
			return
		}
		c := cfg.CanaryEngine.Config()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(c)

	case http.MethodPost:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		var c canary.CanaryConfig
		if err := json.Unmarshal(body, &c); err != nil {
			http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}

		cfg.CanaryEngine.UpdateConfig(c)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(cfg.CanaryEngine.Config())

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
