package docker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateContainerID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid short hex", "a1b2c3d4e5f6", false},
		{"valid long hex", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"valid container name", "my-postgres_db.1", false},
		{"empty string", "", true},
		{"whitespace only", "   ", true},
		{"path traversal attempt", "../../../etc/passwd", true},
		{"slash character", "container/name", true},
		{"backslash character", "container\\name", true},
		{"space character", "my container", true},
		{"control character", "my\ncontainer", true},
		{"starts with hyphen", "-my-container", true},
		{"overly long string", string(make([]byte, 150)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContainerID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContainerID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestRestartContainer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/web-app/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Query().Get("t") != "10" {
			t.Errorf("expected t=10, got %s", r.URL.Query().Get("t"))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1.43/containers/missing-app/restart", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/v1.43/containers/broken-app/restart", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal daemon error"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewCustomClient(server.Client(), server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. Successful restart
	if err := client.RestartContainer(ctx, "web-app", 10); err != nil {
		t.Fatalf("expected successful restart, got %v", err)
	}

	// 2. Container not found
	err := client.RestartContainer(ctx, "missing-app", 10)
	if !errors.Is(err, ErrContainerNotFound) {
		t.Fatalf("expected ErrContainerNotFound, got %v", err)
	}

	// 3. Invalid ID rejected before network call
	if err := client.RestartContainer(ctx, "../bad", 10); !errors.Is(err, ErrInvalidContainerID) {
		t.Fatalf("expected ErrInvalidContainerID, got %v", err)
	}

	// 4. Server error
	if err := client.RestartContainer(ctx, "broken-app", 10); err == nil {
		t.Fatalf("expected error for broken-app, got nil")
	}
}

func TestStopContainer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/web-app/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1.43/containers/already-stopped/stop", func(w http.ResponseWriter, r *http.Request) {
		// 304 Not Modified
		w.WriteHeader(http.StatusNotModified)
	})
	mux.HandleFunc("/v1.43/containers/missing-app/stop", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewCustomClient(server.Client(), server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. Normal stop
	if err := client.StopContainer(ctx, "web-app", 10); err != nil {
		t.Fatalf("expected successful stop, got %v", err)
	}

	// 2. Already stopped (304) should succeed
	if err := client.StopContainer(ctx, "already-stopped", 10); err != nil {
		t.Fatalf("expected 304 to be treated as success, got %v", err)
	}

	// 3. Not found
	if err := client.StopContainer(ctx, "missing-app", 10); !errors.Is(err, ErrContainerNotFound) {
		t.Fatalf("expected ErrContainerNotFound, got %v", err)
	}

	// 4. Invalid container identifier
	if err := client.StopContainer(ctx, "invalid space id", 10); !errors.Is(err, ErrInvalidContainerID) {
		t.Fatalf("expected ErrInvalidContainerID, got %v", err)
	}
}
