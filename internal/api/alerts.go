package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kLauncher1/dock-radar/internal/alert"
	"github.com/kLauncher1/dock-radar/internal/security"
)

// AlertTestRequest parses incoming parameters for manual test webhook dispatch.
type AlertTestRequest struct {
	Channel string `json:"channel"`
}

// AlertTestResponse provides structured verification feedback.
type AlertTestResponse struct {
	Success   bool      `json:"success"`
	Channel   string    `json:"channel,omitempty"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

func (h *HandlerConfig) handleAlertConfig(w http.ResponseWriter, r *http.Request) {
	if h.AlertConfigStore == nil {
		h.AlertConfigStore = alert.NewConfigStore(alert.DefaultConfig())
	}

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h.AlertConfigStore.Get())

	case http.MethodPost:
		if err := security.ValidateLoopbackOrigin(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		if h.RateLimiter != nil && !h.RateLimiter.Allow() {
			w.Header().Set("Retry-After", "2")
			http.Error(w, security.ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
			return
		}

		var newCfg alert.Config
		body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil || len(body) == 0 {
			http.Error(w, "request payload is empty", http.StatusBadRequest)
			return
		}

		if err := json.Unmarshal(body, &newCfg); err != nil {
			http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
			return
		}

		if err := h.AlertConfigStore.Update(newCfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h.AlertConfigStore.Get())

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HandlerConfig) handleAlertEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.AlertDispatcher == nil {
		if h.AlertConfigStore == nil {
			h.AlertConfigStore = alert.NewConfigStore(alert.DefaultConfig())
		}
		h.AlertDispatcher = alert.NewDispatcher(h.AlertConfigStore)
	}

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	events := h.AlertDispatcher.RecentEvents(limit)
	if events == nil {
		events = []alert.Event{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

func (h *HandlerConfig) handleAlertTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := security.ValidateLoopbackOrigin(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if h.RateLimiter != nil && !h.RateLimiter.Allow() {
		w.Header().Set("Retry-After", "2")
		http.Error(w, security.ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
		return
	}

	if h.AlertDispatcher == nil {
		if h.AlertConfigStore == nil {
			h.AlertConfigStore = alert.NewConfigStore(alert.DefaultConfig())
		}
		h.AlertDispatcher = alert.NewDispatcher(h.AlertConfigStore)
	}

	channel := strings.TrimSpace(r.URL.Query().Get("channel"))
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req AlertTestRequest
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err == nil && len(body) > 0 {
			_ = json.Unmarshal(body, &req)
			if req.Channel != "" {
				channel = strings.TrimSpace(req.Channel)
			}
		}
	}

	if channel == "" {
		channel = "all"
	}

	ctx := r.Context()
	err := h.AlertDispatcher.SendTestNotification(ctx, channel)
	if err != nil {
		writeJSONResponse(w, http.StatusBadRequest, AlertTestResponse{
			Success:   false,
			Channel:   channel,
			Message:   err.Error(),
			Timestamp: time.Now().UTC(),
		})
		return
	}

	writeJSONResponse(w, http.StatusOK, AlertTestResponse{
		Success:   true,
		Channel:   channel,
		Message:   fmt.Sprintf("Test alert notification successfully dispatched to %s", channel),
		Timestamp: time.Now().UTC(),
	})
}
