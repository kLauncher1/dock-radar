package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateProjectName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid lowercase", "myproject", false},
		{"valid with hyphen and underscore", "web_app-prod", false},
		{"valid with dot", "core.stack.v1", false},
		{"empty string", "", true},
		{"spaces only", "   ", true},
		{"invalid characters", "my project!", true},
		{"path traversal slash", "my/project", true},
		{"path traversal backslash", "my\\project", true},
		{"too long", strings.Repeat("a", 129), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProjectName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateProjectName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestParseDependsOn(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		deps := ParseDependsOn("")
		if len(deps) != 0 {
			t.Fatalf("expected empty slice, got %v", deps)
		}
	})

	t.Run("comma separated services", func(t *testing.T) {
		deps := ParseDependsOn("db, redis, queue")
		if len(deps) != 3 || deps[0] != "db" || deps[1] != "queue" || deps[2] != "redis" {
			t.Fatalf("unexpected parsed deps: %v", deps)
		}
	})

	t.Run("colon separated with conditions", func(t *testing.T) {
		deps := ParseDependsOn("db:service_healthy,redis:service_started")
		if len(deps) != 2 || deps[0] != "db" || deps[1] != "redis" {
			t.Fatalf("unexpected parsed deps: %v", deps)
		}
	})

	t.Run("json dictionary format", func(t *testing.T) {
		deps := ParseDependsOn(`{"postgres":{"condition":"service_healthy"},"valkey":{"condition":"service_started"}}`)
		if len(deps) != 2 || deps[0] != "postgres" || deps[1] != "valkey" {
			t.Fatalf("unexpected parsed JSON deps: %v", deps)
		}
	})
}

func TestDetectServiceRole(t *testing.T) {
	cases := []struct {
		service string
		image   string
		want    string
	}{
		{"postgres_db", "postgres:16-alpine", "database"},
		{"app_mysql", "mysql:8.0", "database"},
		{"cache", "redis:7-alpine", "cache"},
		{"broker", "rabbitmq:3-management", "queue"},
		{"web_proxy", "nginx:alpine", "gateway"},
		{"caddy_edge", "caddy:2.7", "gateway"},
		{"async_worker", "python-celery:latest", "worker"},
		{"s3_store", "minio/minio:latest", "storage"},
		{"metrics_collector", "prom/prometheus", "service"},
	}

	for _, c := range cases {
		got := DetectServiceRole(c.service, c.image)
		if got != c.want {
			t.Errorf("DetectServiceRole(%q, %q) = %q, want %q", c.service, c.image, got, c.want)
		}
	}
}

func TestExtractComposeStacksAndTopology(t *testing.T) {
	containers := []ContainerSummary{
		{
			ID:     "c11111111111",
			Names:  []string{"/web-stack-nginx-1"},
			Image:  "nginx:alpine",
			State:  "running",
			Status: "Up 2 hours",
			Labels: map[string]string{
				"com.docker.compose.project":             "web-stack",
				"com.docker.compose.service":             "frontend",
				"com.docker.compose.depends_on":          "backend,redis",
				"com.docker.compose.project.working_dir": "/apps/web",
			},
		},
		{
			ID:     "c22222222222",
			Names:  []string{"/web-stack-api-1"},
			Image:  "golang:1.22-alpine",
			State:  "running",
			Status: "Up 2 hours",
			Labels: map[string]string{
				"com.docker.compose.project":    "web-stack",
				"com.docker.compose.service":    "backend",
				"com.docker.compose.depends_on": "db",
			},
		},
		{
			ID:     "c33333333333",
			Names:  []string{"/web-stack-db-1"},
			Image:  "postgres:16-alpine",
			State:  "running",
			Status: "Up 2 hours",
			Labels: map[string]string{
				"com.docker.compose.project": "web-stack",
				"com.docker.compose.service": "db",
			},
		},
		{
			ID:     "c44444444444",
			Names:  []string{"/standalone-busybox"},
			Image:  "busybox",
			State:  "running",
			Status: "Up 1 hour",
			Labels: map[string]string{}, // No compose label
		},
	}

	stacks := ExtractComposeStacks(containers)
	if len(stacks) != 1 {
		t.Fatalf("expected 1 compose stack, got %d", len(stacks))
	}

	stack := stacks[0]
	if stack.Project != "web-stack" {
		t.Errorf("expected stack project web-stack, got %s", stack.Project)
	}
	if stack.TotalServices != 3 {
		t.Errorf("expected 3 services in web-stack, got %d", stack.TotalServices)
	}
	if stack.RunningServices != 3 {
		t.Errorf("expected 3 running services, got %d", stack.RunningServices)
	}
	if stack.Health != "healthy" {
		t.Errorf("expected stack health healthy, got %s", stack.Health)
	}
	if stack.WorkingDir != "/apps/web" {
		t.Errorf("expected working dir /apps/web, got %s", stack.WorkingDir)
	}

	// Verify Topology Nodes & Edges
	if len(stack.Topology.Nodes) != 3 {
		t.Errorf("expected 3 topology nodes, got %d", len(stack.Topology.Nodes))
	}
	if len(stack.Topology.Edges) < 2 {
		t.Errorf("expected at least 2 topology edges, got %d", len(stack.Topology.Edges))
	}

	foundDbEdge := false
	for _, e := range stack.Topology.Edges {
		if e.From == "backend" && e.To == "db" {
			foundDbEdge = true
			break
		}
	}
	if !foundDbEdge {
		t.Errorf("expected edge from backend to db in topology")
	}
}

func TestClient_StackOperations(t *testing.T) {
	mockContainers := []ContainerSummary{
		{
			ID:     "1111aaaa2222",
			Names:  []string{"/app-web-1"},
			State:  "running",
			Status: "Up 1 hour",
			Labels: map[string]string{
				"com.docker.compose.project": "micro-cluster",
				"com.docker.compose.service": "web",
			},
		},
		{
			ID:     "3333bbbb4444",
			Names:  []string{"/app-db-1"},
			State:  "running",
			Status: "Up 1 hour",
			Labels: map[string]string{
				"com.docker.compose.project": "micro-cluster",
				"com.docker.compose.service": "db",
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/v1.43/containers/json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(mockContainers)
			return
		}
		if strings.Contains(path, "/restart") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.Contains(path, "/stop") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := NewCustomClient(ts.Client(), ts.URL)
	ctx := context.Background()

	t.Run("RestartStack success", func(t *testing.T) {
		res, err := client.RestartStack(ctx, "micro-cluster")
		if err != nil {
			t.Fatalf("RestartStack failed: %v", err)
		}
		if res.SuccessCount != 2 || res.FailureCount != 0 {
			t.Fatalf("unexpected RestartStack result: %+v", res)
		}
		if len(res.AffectedContainers) != 2 {
			t.Fatalf("expected 2 affected containers, got %d", len(res.AffectedContainers))
		}
	})

	t.Run("StopStack success", func(t *testing.T) {
		res, err := client.StopStack(ctx, "micro-cluster")
		if err != nil {
			t.Fatalf("StopStack failed: %v", err)
		}
		if res.SuccessCount != 2 || res.FailureCount != 0 {
			t.Fatalf("unexpected StopStack result: %+v", res)
		}
	})

	t.Run("RecreateStack success", func(t *testing.T) {
		res, err := client.RecreateStack(ctx, "micro-cluster")
		if err != nil {
			t.Fatalf("RecreateStack failed: %v", err)
		}
		if res.SuccessCount != 2 || res.FailureCount != 0 {
			t.Fatalf("unexpected RecreateStack result: %+v", res)
		}
	})

	t.Run("Stack operation project not found", func(t *testing.T) {
		_, err := client.RestartStack(ctx, "non-existent")
		if err != ErrProjectNotFound {
			t.Fatalf("expected ErrProjectNotFound, got %v", err)
		}
	})

	t.Run("Stack operation invalid project name", func(t *testing.T) {
		_, err := client.RestartStack(ctx, "invalid/project!name")
		if err != ErrInvalidProjectName {
			t.Fatalf("expected ErrInvalidProjectName, got %v", err)
		}
	})
}
