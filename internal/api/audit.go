package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/security"
)

func (h *HandlerConfig) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.AuditLogger == nil {
		http.Error(w, "audit logger not initialized", http.StatusInternalServerError)
		return
	}

	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if limit > 10000 {
		limit = 10000
	}

	actionFilter := strings.TrimSpace(r.URL.Query().Get("action"))
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))

	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		events := h.AuditLogger.Recent(limit, actionFilter)
		_ = json.NewEncoder(w).Encode(events)
		return
	}

	// Default: NDJSON stream export
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="dock-radar-audit.ndjson"`)

	if err := h.AuditLogger.ExportNDJSON(w, limit, actionFilter); err != nil {
		http.Error(w, "failed to stream audit log: "+err.Error(), http.StatusInternalServerError)
		return
	}
}
