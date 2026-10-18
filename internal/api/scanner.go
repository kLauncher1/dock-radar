package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/scanner"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// ScannerStatusResponse conveys scanner health, metrics, and gating policy.
type ScannerStatusResponse struct {
	Status       scanner.ScannerStatus `json:"status"`
	GatingPolicy scanner.GatingPolicy  `json:"gating_policy"`
	GeneratedAt  time.Time             `json:"generated_at"`
}

// ScannerReportsResponse lists multiple scan reports.
type ScannerReportsResponse struct {
	Reports     []*scanner.ScanReport `json:"reports"`
	TotalCount  int                   `json:"total_count"`
	GeneratedAt time.Time             `json:"generated_at"`
}

// ScanTriggerRequest parses user input for on-demand image or container scans.
type ScanTriggerRequest struct {
	Image       string `json:"image,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
}

// handleScannerStatus handles GET /api/scanner/status.
func (h *HandlerConfig) handleScannerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.ScannerEngine == nil {
		writeJSONResponse(w, http.StatusOK, ScannerStatusResponse{
			Status:       scanner.ScannerStatus{Enabled: false},
			GatingPolicy: scanner.DefaultGatingPolicy(),
			GeneratedAt:  time.Now().UTC(),
		})
		return
	}

	writeJSONResponse(w, http.StatusOK, ScannerStatusResponse{
		Status:       h.ScannerEngine.GetStatus(),
		GatingPolicy: h.ScannerEngine.GetGatingPolicy(),
		GeneratedAt:  time.Now().UTC(),
	})
}

// handleScannerReports handles GET /api/scanner/reports.
func (h *HandlerConfig) handleScannerReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.ScannerEngine == nil {
		writeJSONResponse(w, http.StatusOK, ScannerReportsResponse{
			Reports:     []*scanner.ScanReport{},
			TotalCount:  0,
			GeneratedAt: time.Now().UTC(),
		})
		return
	}

	q := r.URL.Query()
	limit := 50
	if lStr := q.Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}

	filter := scanner.ScanFilter{
		ImageName:    q.Get("image"),
		ContainerID:  q.Get("container_id"),
		GatingStatus: scanner.GatingStatus(strings.ToUpper(q.Get("gating_status"))),
		MinSeverity:  scanner.ParseSeverity(q.Get("min_severity")),
		Limit:        limit,
	}

	reports := h.ScannerEngine.ListReports(filter)
	writeJSONResponse(w, http.StatusOK, ScannerReportsResponse{
		Reports:     reports,
		TotalCount:  len(reports),
		GeneratedAt: time.Now().UTC(),
	})
}

// handleScannerReport handles GET /api/scanner/report?id=...
func (h *HandlerConfig) handleScannerReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.ScannerEngine == nil {
		http.Error(w, "scanner engine not initialized", http.StatusServiceUnavailable)
		return
	}

	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		id = strings.TrimSpace(r.URL.Query().Get("image"))
	}
	if id == "" {
		http.Error(w, "missing required id or image parameter", http.StatusBadRequest)
		return
	}

	report, ok := h.ScannerEngine.GetReport(id)
	if !ok {
		http.Error(w, fmt.Sprintf("report for %q not found", id), http.StatusNotFound)
		return
	}

	writeJSONResponse(w, http.StatusOK, report)
}

// handleScannerScan handles POST /api/scanner/scan.
func (h *HandlerConfig) handleScannerScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if h.ScannerEngine == nil {
		http.Error(w, "scanner engine not initialized", http.StatusServiceUnavailable)
		return
	}

	var req ScanTriggerRequest
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err == nil && len(body) > 0 {
			_ = json.Unmarshal(body, &req)
		}
	}

	if req.Image == "" {
		req.Image = strings.TrimSpace(r.URL.Query().Get("image"))
	}
	if req.ContainerID == "" {
		req.ContainerID = strings.TrimSpace(r.URL.Query().Get("container_id"))
	}

	ctx := r.Context()
	var report *scanner.ScanReport
	var err error

	if req.ContainerID != "" {
		report, err = h.ScannerEngine.ScanContainer(ctx, req.ContainerID)
	} else if req.Image != "" {
		report, err = h.ScannerEngine.ScanImage(ctx, req.Image)
	} else {
		// Scan all active containers
		h.ScannerEngine.ScanActiveContainers(ctx)
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success":   true,
			"message":   "active container scan sweep triggered",
			"timestamp": time.Now().UTC(),
		})
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("scan failed: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, http.StatusOK, report)
}

// handleScannerSBOM handles GET /api/scanner/sbom?id=...&format=spdx|cyclonedx.
func (h *HandlerConfig) handleScannerSBOM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.ScannerEngine == nil {
		http.Error(w, "scanner engine not initialized", http.StatusServiceUnavailable)
		return
	}

	target := strings.TrimSpace(r.URL.Query().Get("id"))
	if target == "" {
		target = strings.TrimSpace(r.URL.Query().Get("image"))
	}
	if target == "" {
		http.Error(w, "missing required id or image parameter", http.StatusBadRequest)
		return
	}

	report, ok := h.ScannerEngine.GetReport(target)
	if !ok {
		// Trigger an ad-hoc scan if not cached
		var err error
		report, err = h.ScannerEngine.ScanImage(r.Context(), target)
		if err != nil {
			http.Error(w, fmt.Sprintf("image not found or scannable: %v", err), http.StatusNotFound)
			return
		}
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	var payload []byte
	var err error
	var filename string

	safeName := strings.ReplaceAll(strings.ReplaceAll(report.ImageName, "/", "_"), ":", "_")

	if format == "cyclonedx" {
		payload, err = scanner.GenerateCycloneDX(report)
		filename = fmt.Sprintf("sbom-%s.cyclonedx.json", safeName)
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	} else {
		payload, err = scanner.GenerateSPDX(report)
		filename = fmt.Sprintf("sbom-%s.spdx.json", safeName)
		w.Header().Set("Content-Type", "application/spdx+json")
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate SBOM: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

// handleScannerGating handles GET/POST /api/scanner/gating.
func (h *HandlerConfig) handleScannerGating(w http.ResponseWriter, r *http.Request) {
	if h.ScannerEngine == nil {
		http.Error(w, "scanner engine not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{
			"policy":       h.ScannerEngine.GetGatingPolicy(),
			"generated_at": time.Now().UTC(),
		})

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		var policy scanner.GatingPolicy
		body, err := io.ReadAll(io.LimitReader(r.Body, 16384))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &policy); err != nil {
			http.Error(w, fmt.Sprintf("invalid gating policy JSON: %v", err), http.StatusBadRequest)
			return
		}

		if err := h.ScannerEngine.UpdateGatingPolicy(policy); err != nil {
			http.Error(w, fmt.Sprintf("failed to update policy: %v", err), http.StatusBadRequest)
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]any{
			"success":   true,
			"message":   "deployment security gating policy updated",
			"policy":    policy,
			"timestamp": time.Now().UTC(),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
