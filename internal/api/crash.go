package api

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/crash"
	"github.com/kLauncher1/dock-radar/internal/security"
)

type crashIngestRequest struct {
	ContainerID   string            `json:"container_id"`
	ContainerName string            `json:"container_name,omitempty"`
	Image         string            `json:"image,omitempty"`
	RawDump       string            `json:"raw_dump"` // text backtrace or base64 binary core
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type crashTestRequest struct {
	ContainerID string `json:"container_id,omitempty"`
}

func (cfg *HandlerConfig) handleCrashStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.CrashEngine == nil {
		http.Error(w, "Crash engine not configured", http.StatusServiceUnavailable)
		return
	}

	status := cfg.CrashEngine.Status()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(status)
}

func (cfg *HandlerConfig) handleCrashReports(w http.ResponseWriter, r *http.Request) {
	if cfg.CrashEngine == nil {
		http.Error(w, "Crash engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !cfg.authorize(w, r, security.RoleViewer) {
			return
		}
		q := r.URL.Query()
		limit := 50
		if lStr := q.Get("limit"); lStr != "" {
			if parsed, err := strconv.Atoi(lStr); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		filter := crash.ReportFilter{
			ContainerID: strings.TrimSpace(q.Get("container_id")),
			Severity:    strings.TrimSpace(q.Get("severity")),
			RootCause:   strings.TrimSpace(q.Get("root_cause")),
			Signature:   strings.TrimSpace(q.Get("signature")),
			Limit:       limit,
		}

		reports := cfg.CrashEngine.Reports(filter)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"reports": reports,
			"count":   len(reports),
		})

	case http.MethodDelete:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		cfg.CrashEngine.ClearReports()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "cleared",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (cfg *HandlerConfig) handleCrashReportDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleViewer) {
		return
	}
	if cfg.CrashEngine == nil {
		http.Error(w, "Crash engine not configured", http.StatusServiceUnavailable)
		return
	}

	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, "Missing required 'id' query parameter", http.StatusBadRequest)
		return
	}

	rep, ok := cfg.CrashEngine.Report(id)
	if !ok || rep == nil {
		http.Error(w, "Crash report not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(rep)
}

func (cfg *HandlerConfig) handleCrashIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.CrashEngine == nil {
		http.Error(w, "Crash engine not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10MB request cap
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var req crashIngestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	req.ContainerID = strings.TrimSpace(req.ContainerID)
	if req.ContainerID == "" {
		http.Error(w, "container_id is required", http.StatusBadRequest)
		return
	}
	if req.RawDump == "" {
		http.Error(w, "raw_dump is required", http.StatusBadRequest)
		return
	}

	// Determine if raw_dump is Base64 encoded or plain text
	var dumpBytes []byte
	if decoded, err := base64.StdEncoding.DecodeString(req.RawDump); err == nil && len(decoded) > 0 {
		dumpBytes = decoded
	} else {
		dumpBytes = []byte(req.RawDump)
	}

	rep, err := cfg.CrashEngine.IngestCrashDump(r.Context(), req.ContainerID, req.ContainerName, req.Image, dumpBytes, req.Metadata)
	if err != nil {
		http.Error(w, "Failed to ingest crash dump: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ingested",
		"report": rep,
	})
}

func (cfg *HandlerConfig) handleCrashTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !cfg.authorize(w, r, security.RoleAdmin) {
		return
	}
	if cfg.CrashEngine == nil {
		http.Error(w, "Crash engine not configured", http.StatusServiceUnavailable)
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
	var req crashTestRequest
	_ = json.Unmarshal(body, &req)

	containerID := strings.TrimSpace(req.ContainerID)
	if containerID == "" {
		containerID = "drill-container-01"
	}

	rep, err := cfg.CrashEngine.TriggerTestCrash(containerID)
	if err != nil {
		http.Error(w, "Failed to trigger test crash drill: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "simulated",
		"report": rep,
	})
}

func (cfg *HandlerConfig) handleCrashConfig(w http.ResponseWriter, r *http.Request) {
	if cfg.CrashEngine == nil {
		http.Error(w, "Crash engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !cfg.authorize(w, r, security.RoleViewer) {
			return
		}
		c := cfg.CrashEngine.Config()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(c)

	case http.MethodPost:
		if !cfg.authorize(w, r, security.RoleAdmin) {
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		var newCfg crash.CrashConfig
		if err := json.Unmarshal(body, &newCfg); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := cfg.CrashEngine.UpdateConfig(newCfg); err != nil {
			http.Error(w, "Invalid configuration: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "updated",
			"config": cfg.CrashEngine.Config(),
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
