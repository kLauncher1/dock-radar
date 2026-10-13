package system

import (
	"os"
	"runtime"
	"time"
)

// Metrics represents real-time host and runtime telemetry.
type Metrics struct {
	Hostname       string    `json:"hostname"`
	OS             string    `json:"os"`
	Arch           string    `json:"arch"`
	NumCPU         int       `json:"num_cpu"`
	NumGoroutine   int       `json:"num_goroutine"`
	AllocMB        float64   `json:"alloc_mb"`
	TotalAllocMB   float64   `json:"total_alloc_mb"`
	SysMB          float64   `json:"sys_mb"`
	NumGC          uint32    `json:"num_gc"`
	UptimeSeconds  int64     `json:"uptime_seconds"`
	CollectedAt    time.Time `json:"collected_at"`
}

var startTime = time.Now()

// CollectTelemetry samples current memory, runtime, and platform metrics.
func CollectTelemetry() Metrics {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}

	return Metrics{
		Hostname:      hostname,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		NumCPU:        runtime.NumCPU(),
		NumGoroutine:  runtime.NumGoroutine(),
		AllocMB:       toMB(mem.Alloc),
		TotalAllocMB:  toMB(mem.TotalAlloc),
		SysMB:         toMB(mem.Sys),
		NumGC:         mem.NumGC,
		UptimeSeconds: int64(time.Since(startTime).Seconds()),
		CollectedAt:   time.Now().UTC(),
	}
}

func toMB(bytes uint64) float64 {
	return float64(bytes) / 1024.0 / 1024.0
}
