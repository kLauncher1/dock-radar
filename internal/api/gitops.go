package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/gitops"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// handleGitOpsStatus serves operational metrics and health overview of the continuous sync engine.
func (h *HandlerConfig) handleGitOpsStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.GitOpsEngine == nil {
		http.Error(w, "gitops engine not initialized", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.GitOpsEngine.Status())
}

// handleGitOpsRepos manages listing, registration, and deletion of tracked Git repositories.
func (h *HandlerConfig) handleGitOpsRepos(w http.ResponseWriter, r *http.Request) {
	if h.GitOpsEngine == nil {
		http.Error(w, "gitops engine not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		repos := h.GitOpsEngine.ListRepos()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"repositories": repos})

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		var repo gitops.GitRepoConfig
		if err := json.NewDecoder(r.Body).Decode(&repo); err != nil {
			http.Error(w, "invalid request json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.GitOpsEngine.AddOrUpdateRepo(repo); err != nil {
			http.Error(w, "failed to configure repository: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"message": "repository configured successfully",
			"id":      repo.ID,
		})

	case http.MethodDelete:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "missing required 'id' query parameter", http.StatusBadRequest)
			return
		}
		if !h.GitOpsEngine.RemoveRepo(id) {
			http.Error(w, "repository not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "deleted_id": id})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGitOpsSync triggers on-demand polling and rollout for a tracked repository.
func (h *HandlerConfig) handleGitOpsSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if h.GitOpsEngine == nil {
		http.Error(w, "gitops engine not initialized", http.StatusServiceUnavailable)
		return
	}

	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, "missing required 'id' query parameter", http.StatusBadRequest)
		return
	}

	record, err := h.GitOpsEngine.SyncRepo(r.Context(), id)
	if err != nil {
		http.Error(w, "sync failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if record == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"message": "repository is already up to date; no rollout needed",
			"id":      id,
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"deployment": record,
	})
}

// handleGitOpsDeploy triggers manual rollout of a specific commit hash.
func (h *HandlerConfig) handleGitOpsDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if h.GitOpsEngine == nil {
		http.Error(w, "gitops engine not initialized", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		RepoID    string `json:"repo_id"`
		CommitSHA string `json:"commit_sha"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request json: "+err.Error(), http.StatusBadRequest)
		return
	}

	req.RepoID = strings.TrimSpace(req.RepoID)
	req.CommitSHA = strings.TrimSpace(req.CommitSHA)
	if req.RepoID == "" || req.CommitSHA == "" {
		http.Error(w, "repo_id and commit_sha are required", http.StatusBadRequest)
		return
	}

	record, err := h.GitOpsEngine.DeployCommit(r.Context(), req.RepoID, req.CommitSHA)
	if err != nil {
		http.Error(w, "deployment failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"deployment": record,
	})
}

// handleGitOpsRollback triggers rollback of an existing deployment record.
func (h *HandlerConfig) handleGitOpsRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}

	if h.GitOpsEngine == nil {
		http.Error(w, "gitops engine not initialized", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		DeploymentID string `json:"deployment_id"`
		Reason       string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request json: "+err.Error(), http.StatusBadRequest)
		return
	}

	req.DeploymentID = strings.TrimSpace(req.DeploymentID)
	if req.DeploymentID == "" {
		http.Error(w, "deployment_id is required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		req.Reason = "manual rollback requested by operator"
	}

	if err := h.GitOpsEngine.RollbackDeployment(r.Context(), req.DeploymentID, req.Reason); err != nil {
		http.Error(w, "rollback failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        "ok",
		"deployment_id": req.DeploymentID,
		"message":       "rollback successfully executed",
	})
}

// handleGitOpsDeployments returns recent rollout records and logs.
func (h *HandlerConfig) handleGitOpsDeployments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !h.authorize(w, r, security.RoleViewer) {
		return
	}

	if h.GitOpsEngine == nil {
		http.Error(w, "gitops engine not initialized", http.StatusServiceUnavailable)
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}

	deploys := h.GitOpsEngine.ListDeployments(limit)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"deployments": deploys,
		"count":       len(deploys),
	})
}

// handleGitOpsWebhook receives push webhooks from GitHub, GitLab, and Gitea.
func (h *HandlerConfig) handleGitOpsWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.GitOpsEngine == nil {
		http.Error(w, "gitops engine not initialized", http.StatusServiceUnavailable)
		return
	}

	// Limit request body to 1 MB to prevent memory exhaustion
	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024*1024))
	if err != nil {
		http.Error(w, "payload too large or failed to read: "+err.Error(), http.StatusBadRequest)
		return
	}

	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	record, err := h.GitOpsEngine.HandleWebhook(r.Context(), payload, headers)
	if err != nil {
		http.Error(w, "webhook processing failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"deployment": record,
	})
}

// handleGitOpsConfig retrieves or updates global GitOps engine configuration.
func (h *HandlerConfig) handleGitOpsConfig(w http.ResponseWriter, r *http.Request) {
	if h.GitOpsEngine == nil {
		http.Error(w, "gitops engine not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		cfg := h.GitOpsEngine.Config()
		if cfg.DefaultWebhookSecret != "" {
			cfg.DefaultWebhookSecret = "****"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		var newCfg gitops.GitOpsConfig
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, "invalid config json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := h.GitOpsEngine.UpdateConfig(newCfg); err != nil {
			http.Error(w, "failed to update config: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"message": "gitops configuration updated",
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
