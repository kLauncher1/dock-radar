package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/logs"
	"github.com/kLauncher1/dock-radar/internal/security"
	"github.com/kLauncher1/dock-radar/internal/storage"
)

// StorageChunksResponse provides a paginated slice of chunk records.
type StorageChunksResponse struct {
	Chunks []*storage.LogChunk `json:"chunks"`
	Total  int                 `json:"total"`
}

// StorageChunkDetailResponse provides chunk metadata and optional log records.
type StorageChunkDetailResponse struct {
	Chunk        *storage.LogChunk `json:"chunk"`
	Entries      []logs.LogEntry   `json:"entries,omitempty"`
	HasLocalFile bool              `json:"has_local_file"`
}

// StorageFlushResponse reports the outcome of a manual buffer flush invocation.
type StorageFlushResponse struct {
	Success       bool                `json:"success"`
	FlushedChunks int                 `json:"flushed_chunks"`
	Chunks        []*storage.LogChunk `json:"chunks"`
}

// StorageConfigResponse exposes active S3 and local disk retention policies.
type StorageConfigResponse struct {
	S3        storage.S3Config        `json:"s3"`
	Retention storage.RetentionConfig `json:"retention"`
}

// StorageConfigUpdateRequest accepts updated configuration values.
type StorageConfigUpdateRequest struct {
	S3        storage.S3Config        `json:"s3"`
	Retention storage.RetentionConfig `json:"retention"`
}

// StorageTestResponse conveys the result of an on-demand S3 connectivity check.
type StorageTestResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// handleStorageStatus reports overall chunk counts, disk byte consumption, and S3 status.
func (h *HandlerConfig) handleStorageStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if h.StorageManager == nil {
		_ = json.NewEncoder(w).Encode(storage.StorageStatus{})
		return
	}

	status := h.StorageManager.Status()
	_ = json.NewEncoder(w).Encode(status)
}

// handleStorageChunks returns indexed log chunks with container, stream, and status filtering.
func (h *HandlerConfig) handleStorageChunks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if h.StorageManager == nil {
		_ = json.NewEncoder(w).Encode(StorageChunksResponse{Chunks: []*storage.LogChunk{}, Total: 0})
		return
	}

	q := r.URL.Query()
	limit := 50
	if l := q.Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 && val <= 500 {
			limit = val
		}
	}

	offset := 0
	if o := q.Get("offset"); o != "" {
		if val, err := strconv.Atoi(o); err == nil && val >= 0 {
			offset = val
		}
	}

	filter := storage.ChunkFilter{
		ContainerID: strings.TrimSpace(q.Get("container")),
		Stream:      strings.TrimSpace(q.Get("stream")),
		S3Status:    strings.TrimSpace(q.Get("s3_status")),
		Limit:       limit,
		Offset:      offset,
	}

	chunks, total := h.StorageManager.ListChunks(filter)
	_ = json.NewEncoder(w).Encode(StorageChunksResponse{
		Chunks: chunks,
		Total:  total,
	})
}

// handleStorageChunk returns specific chunk metadata, unpacked log entries, or the raw .gz file.
func (h *HandlerConfig) handleStorageChunk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.StorageManager == nil {
		http.Error(w, "Storage manager not initialized", http.StatusServiceUnavailable)
		return
	}

	chunkID := strings.TrimSpace(r.URL.Query().Get("id"))
	if chunkID == "" {
		http.Error(w, "Query parameter 'id' is required", http.StatusBadRequest)
		return
	}

	if err := storage.ValidateChunkID(chunkID); err != nil {
		http.Error(w, fmt.Sprintf("Invalid chunk ID format: %v", err), http.StatusBadRequest)
		return
	}

	// Direct raw .gz download path
	if strings.EqualFold(r.URL.Query().Get("download"), "true") {
		data, err := h.StorageManager.ReadChunkBytes(chunkID)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to retrieve chunk bytes: %v", err), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.gz\"", chunkID))
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
		return
	}

	// JSON metadata & optional entry unpack path
	chunk, err := h.StorageManager.GetChunk(chunkID)
	if err != nil {
		http.Error(w, "Chunk not found", http.StatusNotFound)
		return
	}

	resp := StorageChunkDetailResponse{
		Chunk:        chunk,
		HasLocalFile: chunk.LocalPath != "",
	}

	if strings.EqualFold(r.URL.Query().Get("entries"), "true") && chunk.LocalPath != "" {
		entries, err := h.StorageManager.ReadChunkEntries(chunkID)
		if err == nil {
			resp.Entries = entries
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleStorageFlush triggers an immediate manual flush of buffered log entries to disk and S3.
func (h *HandlerConfig) handleStorageFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if h.StorageManager == nil {
		http.Error(w, "Storage manager not initialized", http.StatusServiceUnavailable)
		return
	}

	chunks, err := h.StorageManager.Flush()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	if h.AuditLogger != nil {
		h.AuditLogger.Log(audit.AuditEvent{
			Action: "log_storage_flush",
			Target: "storage",
			Details: map[string]any{
				"flushed_chunks": len(chunks),
			},
		})
	}

	_ = json.NewEncoder(w).Encode(StorageFlushResponse{
		Success:       true,
		FlushedChunks: len(chunks),
		Chunks:        chunks,
	})
}

// handleStorageConfig retrieves or updates storage and S3 configuration.
func (h *HandlerConfig) handleStorageConfig(w http.ResponseWriter, r *http.Request) {
	if h.StorageManager == nil {
		http.Error(w, "Storage manager not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(StorageConfigResponse{
			S3:        h.StorageManager.GetS3Config(),
			Retention: h.StorageManager.GetRetentionConfig(),
		})

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 16384))
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		var req StorageConfigUpdateRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			http.Error(w, fmt.Sprintf("Invalid JSON configuration: %v", err), http.StatusBadRequest)
			return
		}

		if err := h.StorageManager.UpdateConfig(req.S3, req.Retention); err != nil {
			http.Error(w, fmt.Sprintf("Configuration validation error: %v", err), http.StatusBadRequest)
			return
		}

		if h.AuditLogger != nil {
			h.AuditLogger.Log(audit.AuditEvent{
				Action: "log_storage_config_update",
				Target: "storage",
				Details: map[string]any{
					"s3_enabled": req.S3.IsEnabled(),
					"bucket":     req.S3.Bucket,
					"max_chunks": req.Retention.MaxLocalChunks,
				},
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(StorageConfigResponse{
			S3:        h.StorageManager.GetS3Config(),
			Retention: h.StorageManager.GetRetentionConfig(),
		})

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleStorageTest probes S3 bucket connectivity using the specified or stored configuration.
func (h *HandlerConfig) handleStorageTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if h.StorageManager == nil {
		http.Error(w, "Storage manager not initialized", http.StatusServiceUnavailable)
		return
	}

	var testCfg storage.S3Config
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err == nil && len(bodyBytes) > 0 {
		_ = json.Unmarshal(bodyBytes, &testCfg)
	}

	if !testCfg.IsEnabled() {
		// Fall back to active stored config
		testCfg = h.StorageManager.GetS3Config()
	}

	w.Header().Set("Content-Type", "application/json")
	testCtx, testCancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer testCancel()

	if err := h.StorageManager.TestS3Connection(testCtx, testCfg); err != nil {
		_ = json.NewEncoder(w).Encode(StorageTestResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(StorageTestResponse{
		Success: true,
		Message: "S3 connection and bucket access successfully verified.",
	})
}
