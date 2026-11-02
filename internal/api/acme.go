package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/kLauncher1/dock-radar/internal/acme"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// IssueCertRequest represents input payload for requesting a new certificate.
type IssueCertRequest struct {
	Domain        string             `json:"domain"`
	SANs          []string           `json:"sans"`
	Provider      acme.ACMEProvider  `json:"provider"`
	ChallengeType acme.ChallengeType `json:"challenge_type"`
}

// DomainActionRequest represents input payload for renew/revoke actions.
type DomainActionRequest struct {
	Domain string `json:"domain"`
}

func (h *HandlerConfig) handleACMEStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.ACMEEngine == nil {
		http.Error(w, "acme engine not configured", http.StatusServiceUnavailable)
		return
	}

	st := h.ACMEEngine.Status()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func (h *HandlerConfig) handleACMECertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.ACMEEngine == nil {
		http.Error(w, "acme engine not configured", http.StatusServiceUnavailable)
		return
	}

	certs := h.ACMEEngine.Router().List()
	summaries := make([]acme.CertSummary, 0, len(certs))
	threshold := h.ACMEEngine.Config().RenewThresholdDays

	for _, c := range certs {
		c.DaysUntilExpire = acme.CalculateDaysUntilExpire(c.NotAfter)
		st := acme.EvaluateStatus(c.NotAfter, threshold)
		if c.Status != acme.CertStatusRenewing && c.Status != acme.CertStatusFailed {
			c.Status = st
		}

		summaries = append(summaries, acme.CertSummary{
			Domain:            c.Domain,
			SANs:              c.SANs,
			Issuer:            c.Issuer,
			FingerprintSHA256: c.FingerprintSHA256,
			NotAfter:          c.NotAfter,
			DaysUntilExpire:   c.DaysUntilExpire,
			Status:            c.Status,
			AutoRenew:         c.AutoRenew,
			Provider:          c.Provider,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summaries)
}

func (h *HandlerConfig) handleACMECertificateDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.ACMEEngine == nil {
		http.Error(w, "acme engine not configured", http.StatusServiceUnavailable)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		http.Error(w, "missing domain query parameter", http.StatusBadRequest)
		return
	}

	cert, ok := h.ACMEEngine.Router().Get(domain)
	if !ok || cert == nil {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}

	cert.DaysUntilExpire = acme.CalculateDaysUntilExpire(cert.NotAfter)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cert)
}

func (h *HandlerConfig) handleACMEOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}
	if h.ACMEEngine == nil {
		http.Error(w, "acme engine not configured", http.StatusServiceUnavailable)
		return
	}

	var req IssueCertRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*64))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Provider == "" {
		req.Provider = h.ACMEEngine.Config().Provider
	}
	if req.ChallengeType == "" {
		req.ChallengeType = h.ACMEEngine.Config().ChallengeType
	}

	cert, err := h.ACMEEngine.IssueCertificate(r.Context(), req.Domain, req.SANs, req.Provider, req.ChallengeType)
	if err != nil {
		http.Error(w, "failed to issue certificate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(cert)
}

func (h *HandlerConfig) handleACMERenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}
	if h.ACMEEngine == nil {
		http.Error(w, "acme engine not configured", http.StatusServiceUnavailable)
		return
	}

	var req DomainActionRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*32))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	renewed, err := h.ACMEEngine.RenewCertificate(r.Context(), req.Domain)
	if err != nil {
		http.Error(w, "renewal failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(renewed)
}

func (h *HandlerConfig) handleACMERevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}
	if h.ACMEEngine == nil {
		http.Error(w, "acme engine not configured", http.StatusServiceUnavailable)
		return
	}

	var req DomainActionRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*32))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.ACMEEngine.RevokeCertificate(r.Context(), req.Domain); err != nil {
		http.Error(w, "revocation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"domain":  req.Domain,
		"message": "certificate revoked and removed from dynamic SNI routes",
	})
}

func (h *HandlerConfig) handleACMEChallenges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleViewer) {
		return
	}
	if h.ACMEEngine == nil {
		http.Error(w, "acme engine not configured", http.StatusServiceUnavailable)
		return
	}

	challenges := h.ACMEEngine.ListChallenges()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(challenges)
}

func (h *HandlerConfig) handleACMEDNSChallengeComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorize(w, r, security.RoleAdmin) {
		return
	}
	if h.ACMEEngine == nil {
		http.Error(w, "acme engine not configured", http.StatusServiceUnavailable)
		return
	}

	var req DomainActionRequest
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1024*32))
	_ = json.Unmarshal(body, &req)

	if !h.ACMEEngine.CompleteDNS01Challenge(req.Domain) {
		http.Error(w, "no active dns-01 challenge found for domain", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"domain":   req.Domain,
		"verified": true,
	})
}

func (h *HandlerConfig) handleACMEConfig(w http.ResponseWriter, r *http.Request) {
	if h.ACMEEngine == nil {
		http.Error(w, "acme engine not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, security.RoleViewer) {
			return
		}
		cfg := h.ACMEEngine.Config()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)

	case http.MethodPost:
		if !h.authorize(w, r, security.RoleAdmin) {
			return
		}
		var newCfg acme.ACMEConfig
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024*64))
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &newCfg); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}

		user := "admin"
		clientIP := r.RemoteAddr
		if err := h.ACMEEngine.UpdateConfig(newCfg, user, clientIP); err != nil {
			http.Error(w, "failed to update config: "+err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"config":  h.ACMEEngine.Config(),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleACMEHTTP01Challenge responds to automated ACME HTTP-01 verification requests from Let's Encrypt / CAs.
func (h *HandlerConfig) handleACMEHTTP01Challenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.ACMEEngine == nil {
		http.NotFound(w, r)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	token = strings.TrimSpace(token)
	if token == "" {
		http.NotFound(w, r)
		return
	}

	keyAuth, found := h.ACMEEngine.GetHTTP01KeyAuthorization(token)
	if !found || keyAuth == "" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(keyAuth))
}
