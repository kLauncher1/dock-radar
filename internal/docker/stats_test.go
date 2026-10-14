package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCalculateCPUPercent(t *testing.T) {
	cpu := RawCPUStats{
		CPUUsage: RawCPUUsage{
			TotalUsage:  200000000,
			PercpuUsage: []uint64{100000000, 100000000},
		},
		SystemCPUUsage: 2000000000,
		OnlineCPUs:     2,
	}
	preCPU := RawCPUStats{
		CPUUsage: RawCPUUsage{
			TotalUsage: 100000000,
		},
		SystemCPUUsage: 1000000000,
		OnlineCPUs:     2,
	}

	percent := CalculateCPUPercent(cpu, preCPU)
	// cpuDelta = 100M, systemDelta = 1000M, onlineCPUs = 2
	// percent = (100M / 1000M) * 2 * 100 = 20.0%
	if percent < 19.9 || percent > 20.1 {
		t.Fatalf("expected ~20%% CPU usage, got %f", percent)
	}

	// Zero delta test
	if CalculateCPUPercent(preCPU, preCPU) != 0.0 {
		t.Fatalf("expected 0%% for identical cpu measurements")
	}
}

func TestCalculateEffectiveMemory(t *testing.T) {
	mem := RawMemoryStats{
		Usage: 104857600, // 100 MB
		Limit: 209715200, // 200 MB
		Stats: map[string]uint64{
			"inactive_file": 20971520, // 20 MB cache
		},
	}

	usage, limit, percent := CalculateEffectiveMemory(mem)
	if usage != 83886080 { // 80 MB
		t.Fatalf("expected 80 MB effective usage, got %d", usage)
	}
	if limit != 209715200 {
		t.Fatalf("expected 200 MB limit, got %d", limit)
	}
	if percent < 39.9 || percent > 40.1 {
		t.Fatalf("expected ~40%% memory usage, got %f", percent)
	}
}

func TestGetContainerStats_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.43/containers/web-app-1/stats" {
			http.NotFound(w, r)
			return
		}

		resp := RawContainerStatsResponse{
			Read: time.Now().UTC(),
			Name: "/web-app-1",
			ID:   "web-app-1",
			MemoryStats: RawMemoryStats{
				Usage: 52428800,  // 50 MB
				Limit: 104857600, // 100 MB
			},
			CPUStats: RawCPUStats{
				CPUUsage:       RawCPUUsage{TotalUsage: 50000000},
				SystemCPUUsage: 500000000,
				OnlineCPUs:     1,
			},
			PreCPUStats: RawCPUStats{
				CPUUsage:       RawCPUUsage{TotalUsage: 0},
				SystemCPUUsage: 0,
				OnlineCPUs:     1,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := NewCustomClient(ts.Client(), ts.URL)
	stats, err := client.GetContainerStats(context.Background(), "web-app-1")
	if err != nil {
		t.Fatalf("unexpected error fetching stats: %v", err)
	}

	if stats.Name != "web-app-1" {
		t.Fatalf("expected container name 'web-app-1', got '%s'", stats.Name)
	}
	if stats.MemoryUsage != 52428800 {
		t.Fatalf("expected 50MB memory usage, got %d", stats.MemoryUsage)
	}
	if stats.MemoryPercent < 49.9 || stats.MemoryPercent > 50.1 {
		t.Fatalf("expected 50%% memory percent, got %f", stats.MemoryPercent)
	}
}

func TestGetContainerStats_Errors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client := NewCustomClient(ts.Client(), ts.URL)

	// Invalid ID
	_, err := client.GetContainerStats(context.Background(), "invalid/id")
	if err != ErrInvalidContainerID {
		t.Fatalf("expected ErrInvalidContainerID, got %v", err)
	}

	// 404 Not Found
	_, err = client.GetContainerStats(context.Background(), "missing-container")
	if err != ErrContainerNotFound {
		t.Fatalf("expected ErrContainerNotFound, got %v", err)
	}
}
