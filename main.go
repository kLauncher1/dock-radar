package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/kLauncher1/dock-radar/internal/docker"
	"github.com/kLauncher1/dock-radar/internal/system"
)

//go:embed web/dist/*
var embeddedWeb embed.FS

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9080"
	}

	dockerClient := docker.NewClient()

	mux := http.NewServeMux()

	// API: Real-time system telemetry
	mux.HandleFunc("/api/system", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		metrics := system.CollectTelemetry()
		_ = json.NewEncoder(w).Encode(metrics)
	})

	// API: Docker daemon & container inspection
	mux.HandleFunc("/api/docker", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := dockerClient.InspectContainers()
		_ = json.NewEncoder(w).Encode(status)
	})

	// Embedded Static UI
	subFS, err := fs.Sub(embeddedWeb, "web/dist")
	if err != nil {
		log.Fatalf("Failed to initialize embedded web filesystem: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(subFS)))

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	fmt.Println("=========================================================")
	fmt.Println(" 🚀 Dock-Radar · Single-Binary Container & System Monitor")
	fmt.Printf(" 📡 Web Dashboard Live at http://localhost:%s\n", port)
	fmt.Println(" 💡 Embed Mode: 100% Self-Contained Zero-Dependency Binary")
	fmt.Println("=========================================================")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
