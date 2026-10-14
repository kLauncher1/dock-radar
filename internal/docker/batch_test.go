package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClient_RestartAll_Success(t *testing.T) {
	var restartCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1.43/containers/json"):
			containers := []ContainerSummary{
				{ID: "c1", Names: []string{"/web-nginx"}, State: "running"},
				{ID: "c2", Names: []string{"/api-node"}, State: "running"},
				{ID: "c3", Names: []string{"/old-job"}, State: "exited"},
			}
			_ = json.NewEncoder(w).Encode(containers)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/restart"):
			restartCount.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewCustomClient(server.Client(), server.URL)
	summary, err := client.RestartAll(context.Background(), 5)
	if err != nil {
		t.Fatalf("RestartAll failed: %v", err)
	}

	if summary.Total != 2 {
		t.Errorf("expected 2 total targets, got %d", summary.Total)
	}
	if summary.Succeeded != 2 {
		t.Errorf("expected 2 succeeded, got %d", summary.Succeeded)
	}
	if summary.Failed != 0 {
		t.Errorf("expected 0 failed, got %d", summary.Failed)
	}
	if int(restartCount.Load()) != 2 {
		t.Errorf("expected 2 restart calls, got %d", restartCount.Load())
	}
}

func TestClient_RestartAll_PartialFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1.43/containers/json"):
			containers := []ContainerSummary{
				{ID: "c1", Names: []string{"/success-svc"}, State: "running"},
				{ID: "c2", Names: []string{"/fail-svc"}, State: "running"},
			}
			_ = json.NewEncoder(w).Encode(containers)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/c1/restart"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/c2/restart"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("failed to restart"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewCustomClient(server.Client(), server.URL)
	summary, err := client.RestartAll(context.Background(), 5)
	if err != nil {
		t.Fatalf("RestartAll failed: %v", err)
	}

	if summary.Total != 2 {
		t.Errorf("expected 2 total, got %d", summary.Total)
	}
	if summary.Succeeded != 1 {
		t.Errorf("expected 1 succeeded, got %d", summary.Succeeded)
	}
	if summary.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", summary.Failed)
	}
}

func TestClient_StopAll_Success(t *testing.T) {
	var stopCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1.43/containers/json"):
			containers := []ContainerSummary{
				{ID: "c1", Names: []string{"/redis"}, State: "running"},
				{ID: "c2", Names: []string{"/stopped-db"}, State: "exited"},
			}
			_ = json.NewEncoder(w).Encode(containers)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/stop"):
			stopCount.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewCustomClient(server.Client(), server.URL)
	summary, err := client.StopAll(context.Background(), 5)
	if err != nil {
		t.Fatalf("StopAll failed: %v", err)
	}

	if summary.Total != 1 || summary.Succeeded != 1 {
		t.Errorf("expected 1 total and 1 succeeded, got total %d succeeded %d", summary.Total, summary.Succeeded)
	}
	if int(stopCount.Load()) != 1 {
		t.Errorf("expected 1 stop call, got %d", stopCount.Load())
	}
}

func TestClient_PruneContainers_EndpointSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1.43/containers/prune" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(dockerPruneAPIResponse{
				ContainersDeleted: []string{"c_dead1", "c_dead2"},
				SpaceReclaimed:    4096000,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewCustomClient(server.Client(), server.URL)
	report, err := client.PruneContainers(context.Background())
	if err != nil {
		t.Fatalf("PruneContainers failed: %v", err)
	}

	if len(report.ContainersDeleted) != 2 {
		t.Fatalf("expected 2 deleted containers, got %d", len(report.ContainersDeleted))
	}
	if report.SpaceReclaimed != 4096000 {
		t.Errorf("expected 4096000 space reclaimed, got %d", report.SpaceReclaimed)
	}
}

func TestClient_PruneContainers_FallbackOnEndpointUnavailable(t *testing.T) {
	var deletedList []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1.43/containers/prune":
			// Simulate endpoint not supported by older docker or custom socket
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1.43/containers/json"):
			containers := []ContainerSummary{
				{ID: "c_active", State: "running"},
				{ID: "c_exited", State: "exited"},
				{ID: "c_dead", State: "dead"},
			}
			_ = json.NewEncoder(w).Encode(containers)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1.43/containers/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1.43/containers/")
			deletedList = append(deletedList, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewCustomClient(server.Client(), server.URL)
	report, err := client.PruneContainers(context.Background())
	if err != nil {
		t.Fatalf("PruneContainers fallback failed: %v", err)
	}

	if len(report.ContainersDeleted) != 2 {
		t.Fatalf("expected 2 deleted containers, got %d", len(report.ContainersDeleted))
	}
	if report.ContainersDeleted[0] != "c_exited" || report.ContainersDeleted[1] != "c_dead" {
		t.Errorf("unexpected deleted IDs: %+v", report.ContainersDeleted)
	}
}

func TestClient_BatchOperations_OfflineDaemon(t *testing.T) {
	client := NewCustomClient(nil, "http://127.0.0.1:59999")

	_, errRestart := client.RestartAll(context.Background(), 5)
	if errRestart == nil {
		t.Errorf("expected error from offline daemon on RestartAll")
	}

	_, errStop := client.StopAll(context.Background(), 5)
	if errStop == nil {
		t.Errorf("expected error from offline daemon on StopAll")
	}

	_, errPrune := client.PruneContainers(context.Background())
	if errPrune == nil {
		t.Errorf("expected error from offline daemon on PruneContainers")
	}
}
