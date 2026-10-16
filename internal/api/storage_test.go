package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/kLauncher1/dock-radar/internal/audit"
	"github.com/kLauncher1/dock-radar/internal/logs"
	"github.com/kLauncher1/dock-radar/internal/security"
	"github.com/kLauncher1/dock-radar/internal/storage"
)

func setupTestStorageServer(t *testing.T) (*httptest.Server, *storage.Manager, *audit.Logger, string) {
	tempDir, err := os.MkdirTemp("", "dock_radar_api_storage_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	s3Cfg := storage.DefaultS3Config()
	retCfg := storage.DefaultRetentionConfig()
	retCfg.ChunkSizeEntries = 10

	mgr, err := storage.NewManager(tempDir, s3Cfg, retCfg)
	if err != nil {
		t.Fatalf("failed to create storage manager: %v", err)
	}

	auditLogger := audit.NewLogger(500)
	tokenAuth := security.NewTokenAuth("admin-secret-token", "viewer-secret-token", true)

	mux := http.NewServeMux()
	cfg := &HandlerConfig{
		StorageManager: mgr,
		AuditLogger:    auditLogger,
		TokenAuth:      tokenAuth,
		AllowRemote:    true,
	}

	mux.HandleFunc("/api/logs/storage/status", cfg.handleStorageStatus)
	mux.HandleFunc("/api/logs/storage/chunks", cfg.handleStorageChunks)
	mux.HandleFunc("/api/logs/storage/chunk", cfg.handleStorageChunk)
	mux.HandleFunc("/api/logs/storage/flush", cfg.handleStorageFlush)
	mux.HandleFunc("/api/logs/storage/config", cfg.handleStorageConfig)
	mux.HandleFunc("/api/logs/storage/test", cfg.handleStorageTest)

	server := httptest.NewServer(mux)
	return server, mgr, auditLogger, tempDir
}

func TestStorageAPI_StatusAndChunks(t *testing.T) {
	server, mgr, _, tempDir := setupTestStorageServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)

	// Ingest some entries and flush
	for i := 0; i < 10; i++ {
		mgr.Ingest(logs.LogEntry{
			ID:        "web-container",
			Stream:    "stdout",
			Timestamp: time.Now().UTC(),
			Message:   "Application listening on port 80",
		})
	}
	_, err := mgr.Flush()
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	client := server.Client()

	// 1. GET /api/logs/storage/status with viewer token
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/logs/storage/status", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("status request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var status storage.StorageStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("status decode error: %v", err)
	}
	if status.TotalChunks != 1 || status.LocalChunks != 1 {
		t.Fatalf("expected 1 chunk in status, got %+v", status)
	}

	// 2. GET /api/logs/storage/chunks
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/api/logs/storage/chunks?container=web&limit=10", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("chunks request failed: %v", err)
	}
	defer resp.Body.Close()

	var chunksResp StorageChunksResponse
	if err := json.NewDecoder(resp.Body).Decode(&chunksResp); err != nil {
		t.Fatalf("chunks decode error: %v", err)
	}
	if chunksResp.Total != 1 || len(chunksResp.Chunks) != 1 {
		t.Fatalf("expected 1 chunk returned, got total=%d len=%d", chunksResp.Total, len(chunksResp.Chunks))
	}

	chunkID := chunksResp.Chunks[0].ID

	// 3. GET /api/logs/storage/chunk?id=<id>&entries=true
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/api/logs/storage/chunk?id="+chunkID+"&entries=true", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("chunk detail request failed: %v", err)
	}
	defer resp.Body.Close()

	var detailResp StorageChunkDetailResponse
	if err := json.NewDecoder(resp.Body).Decode(&detailResp); err != nil {
		t.Fatalf("chunk detail decode error: %v", err)
	}
	if len(detailResp.Entries) != 10 {
		t.Fatalf("expected 10 entries unpacked, got %d", len(detailResp.Entries))
	}

	// 4. GET /api/logs/storage/chunk?id=<id>&download=true
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/api/logs/storage/chunk?id="+chunkID+"&download=true", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("chunk download request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Type") != "application/gzip" {
		t.Fatalf("expected Content-Type application/gzip, got %s", resp.Header.Get("Content-Type"))
	}
	data, _ := io.ReadAll(resp.Body)
	if len(data) == 0 {
		t.Fatalf("expected downloaded gzip bytes, got empty")
	}
}

func TestStorageAPI_FlushAndRBAC(t *testing.T) {
	server, _, auditLogger, tempDir := setupTestStorageServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)

	client := server.Client()

	// 1. Viewer trying to POST /api/logs/storage/flush -> should be Forbidden (403)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/logs/storage/flush", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("flush request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer on flush, got %d", resp.StatusCode)
	}

	// 2. Admin trying to POST /api/logs/storage/flush -> should succeed (200)
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/api/logs/storage/flush", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("admin flush request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for admin on flush, got %d", resp.StatusCode)
	}

	var flushResp StorageFlushResponse
	if err := json.NewDecoder(resp.Body).Decode(&flushResp); err != nil {
		t.Fatalf("flush decode error: %v", err)
	}
	if !flushResp.Success {
		t.Fatalf("expected flush success=true")
	}

	// Verify audit log entry
	events := auditLogger.Recent(10, "")
	foundAudit := false
	for _, e := range events {
		if e.Action == "log_storage_flush" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Fatalf("audit event for log_storage_flush not found")
	}
}

func TestStorageAPI_ConfigAndTestConnection(t *testing.T) {
	server, _, _, tempDir := setupTestStorageServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)

	// Mock S3 backend
	mockS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockS3.Close()

	client := server.Client()

	// 1. GET /api/logs/storage/config with viewer token
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/logs/storage/config", nil)
	req.Header.Set("Authorization", "Bearer viewer-secret-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("config get failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for config get, got %d", resp.StatusCode)
	}

	// 2. POST /api/logs/storage/config with admin token
	updatePayload := StorageConfigUpdateRequest{
		S3: storage.S3Config{
			Endpoint:       mockS3.URL,
			Region:         "us-east-1",
			Bucket:         "radar-logs",
			Prefix:         "archive",
			AccessKey:      "MOCKACCESS",
			SecretKey:      "MOCKSECRETKEY",
			ForcePathStyle: true,
		},
		Retention: storage.DefaultRetentionConfig(),
	}
	payloadBytes, _ := json.Marshal(updatePayload)

	req, _ = http.NewRequest(http.MethodPost, server.URL+"/api/logs/storage/config", bytes.NewReader(payloadBytes))
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("config post failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for config post, got %d", resp.StatusCode)
	}

	var updatedConfig StorageConfigResponse
	_ = json.NewDecoder(resp.Body).Decode(&updatedConfig)
	if updatedConfig.S3.Bucket != "radar-logs" {
		t.Fatalf("expected bucket radar-logs, got %s", updatedConfig.S3.Bucket)
	}

	// 3. POST /api/logs/storage/test with admin token
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/api/logs/storage/test", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("test request failed: %v", err)
	}
	defer resp.Body.Close()

	var testResp StorageTestResponse
	_ = json.NewDecoder(resp.Body).Decode(&testResp)
	if !testResp.Success {
		t.Fatalf("expected test connection to succeed against mock S3: %s", testResp.Error)
	}
}

func TestStorageAPI_ChunkPathTraversalDefense(t *testing.T) {
	server, _, _, tempDir := setupTestStorageServer(t)
	defer server.Close()
	defer os.RemoveAll(tempDir)

	client := server.Client()

	badIDs := []string{
		"../traversal",
		"..%2Ftraversal",
		"/etc/passwd",
		"chunk-123/../../secret",
		"chunk;rm",
		"chunk%20space",
	}

	for _, badID := range badIDs {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/logs/storage/chunk?id="+badID, nil)
		req.Header.Set("Authorization", "Bearer viewer-secret-token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed for ID %s: %v", badID, err)
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected HTTP 400 Bad Request for path traversal / invalid ID %q, got %d", badID, resp.StatusCode)
		}
	}
}
