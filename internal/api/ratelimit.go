package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/ratelimit"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// RateLimitStatusResponse conveys rate limiter telemetry and state.
type RateLimitStatusResponse struct {
	Status      ratelimit.LimiterStatus `json:"status"`
	GeneratedAt time.Time               `json:"generated_at"`
}

// TenantQuotasResponse lists configured tenant quotas.
type TenantQuotasResponse struct {
	Tenants     []*ratelimit.TenantQuota `json:"tenants"`
	TotalCount  int                      `json:"total_count"`
	GeneratedAt time.Time                `json:"generated_at"`
}

// BannedIPsResponse lists active IP bans.
type BannedIPsResponse struct {
	Bans        []*ratelimit.IPBanRecord `json:"bans"`
	TotalCount  int                      `json:"total_count"`
	GeneratedAt time.Time                `json:"generated_at"`
}

// BanIPRequest parses manual ban parameters.
type BanIPRequest struct {
	IP              string `json:"ip"`
	Reason          string `json:"reason,omitempty"`
	DurationSeconds int    `json:"duration_seconds,omitempty"`
}

// SyncResponse returns mesh synchronization results.
type SyncResponse struct {
	Success      bool   `json:"success"`
	AppliedBans  int    `json:"applied_bans"`
	Message      string `json:"message"`
	NodeID       string `json:"node_id"`
	Timestamp    int64  `json:"timestamp"`
}

// handleRateLimitStatus handles GET /api/ratelimit/status.
func (h *HandlerConfig) handleRateLimitStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.RateLimitEngine == nil {
		writeJSONResponse(w, http.StatusOK, RateLimitStatusResponse{
			Status:      ratelimit.LimiterStatus{Enabled: false},
			GeneratedAt: time.Now().UTC(),
		})
		return
	}

	writeJSONResponse(w, http.StatusOK, RateLimitStatusResponse{
		Status:      h.RateLimitEngine.Status(),
		GeneratedAt: time.Now().UTC(),
	})
}

// handleRateLimitTenants handles GET, POST, DELETE /api/ratelimit/tenants.
func (h *HandlerConfig) handleRateLimitTenants(w http.ResponseWriter, r *http.Request) {
	if h.RateLimitEngine == nil {
		http.Error(w, "rate limit engine is not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		quotas := h.RateLimitEngine.ListTenantQuotas()
		writeJSONResponse(w, http.StatusOK, TenantQuotasResponse{
			Tenants:     quotas,
			TotalCount:  len(quotas),
			GeneratedAt: time.Now().UTC(),
		})

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		var q ratelimit.TenantQuota
		body, err := io.ReadAll(io.LimitReader(r.Body, 32768))
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &q); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON format: %v", err), http.StatusBadRequest)
			return
		}

		if err := h.RateLimitEngine.SetTenantQuota(q); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success": true,
			"message": fmt.Sprintf("tenant quota configured for %s", q.TenantID),
			"tenant":  q,
		})

	case http.MethodDelete:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		tenantID := strings.TrimSpace(r.URL.Query().Get("id"))
		if tenantID == "" {
			// Try body
			var body struct {
				ID string `json:"id"`
			}
			data, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			_ = json.Unmarshal(data, &body)
			tenantID = strings.TrimSpace(body.ID)
		}

		if tenantID == "" {
			http.Error(w, "tenant id is required (query parameter 'id')", http.StatusBadRequest)
			return
		}

		if !h.RateLimitEngine.DeleteTenantQuota(tenantID) {
			http.Error(w, fmt.Sprintf("tenant %s not found", tenantID), http.StatusNotFound)
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success": true,
			"message": fmt.Sprintf("tenant %s quota deleted", tenantID),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRateLimitBans handles GET, POST, DELETE /api/ratelimit/bans.
func (h *HandlerConfig) handleRateLimitBans(w http.ResponseWriter, r *http.Request) {
	if h.RateLimitEngine == nil {
		http.Error(w, "rate limit engine is not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		bans := h.RateLimitEngine.ListBannedIPs()
		writeJSONResponse(w, http.StatusOK, BannedIPsResponse{
			Bans:        bans,
			TotalCount:  len(bans),
			GeneratedAt: time.Now().UTC(),
		})

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		var req BanIPRequest
		body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
			return
		}

		duration := 15 * time.Minute
		if req.DurationSeconds > 0 {
			duration = time.Duration(req.DurationSeconds) * time.Second
		}

		record, err := h.RateLimitEngine.BanIP(req.IP, req.Reason, duration, "admin-api")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success": true,
			"message": fmt.Sprintf("IP %s successfully banned until %v", record.IP, record.ExpiresAt.UTC()),
			"ban":     record,
		})

	case http.MethodDelete:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		targetIP := strings.TrimSpace(r.URL.Query().Get("ip"))
		if targetIP == "" {
			var body struct {
				IP string `json:"ip"`
			}
			data, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			_ = json.Unmarshal(data, &body)
			targetIP = strings.TrimSpace(body.IP)
		}

		if targetIP == "" {
			http.Error(w, "ip is required (query parameter 'ip')", http.StatusBadRequest)
			return
		}

		if !h.RateLimitEngine.UnbanIP(targetIP) {
			http.Error(w, fmt.Sprintf("IP %s was not found in active bans list", targetIP), http.StatusNotFound)
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success": true,
			"message": fmt.Sprintf("IP %s unbanned", targetIP),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRateLimitSync handles POST /api/ratelimit/sync for mesh peers.
func (h *HandlerConfig) handleRateLimitSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}
	if h.RateLimitEngine == nil {
		http.Error(w, "rate limit engine is not initialized", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 131072)) // 128KB max
	if err != nil {
		http.Error(w, "failed to read sync payload", http.StatusBadRequest)
		return
	}

	payload, err := ratelimit.DeserializeSyncPayload(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid sync payload format: %v", err), http.StatusBadRequest)
		return
	}

	applied, err := h.RateLimitEngine.IngestSyncPayload(payload)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to verify and ingest sync payload: %v", err), http.StatusForbidden)
		return
	}

	writeJSONResponse(w, http.StatusOK, SyncResponse{
		Success:     true,
		AppliedBans: applied,
		Message:     fmt.Sprintf("successfully processed sync payload from peer %s", payload.NodeID),
		NodeID:      payload.NodeID,
		Timestamp:   time.Now().Unix(),
	})
}

// handleRateLimitConfig handles GET, POST /api/ratelimit/config.
func (h *HandlerConfig) handleRateLimitConfig(w http.ResponseWriter, r *http.Request) {
	if h.RateLimitEngine == nil {
		http.Error(w, "rate limit engine is not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		writeJSONResponse(w, http.StatusOK, h.RateLimitEngine.Config())

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		var cfg ratelimit.LimiterConfig
		body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &cfg); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON configuration: %v", err), http.StatusBadRequest)
			return
		}

		if err := h.RateLimitEngine.UpdateConfig(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Action:   "ratelimit_config_update",
				Target:   "ratelimit",
				Actor:    "admin",
				ClientIP: "127.0.0.1",
				Status:   "success",
			})
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success": true,
			"message": "rate limiter configuration updated successfully",
			"config":  h.RateLimitEngine.Config(),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}


