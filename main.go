package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/kLauncher1/dock-radar/internal/api"
	"github.com/kLauncher1/dock-radar/internal/docker"
)

//go:embed web/dist/*
var embeddedWeb embed.FS

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9080"
	}

	dockerClient := docker.NewClient()

	subFS, err := fs.Sub(embeddedWeb, "web/dist")
	if err != nil {
		log.Fatalf("Failed to initialize embedded web filesystem: %v", err)
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, dockerClient, subFS)

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
