package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/PratSins/FrameVerse-Auth/config"
	"github.com/PratSins/FrameVerse-Auth/internal"
	"github.com/joho/godotenv"
)

func main() {
	// Reads from local .env file automatically in local development
	_ = godotenv.Load()

	cfg := config.Load()
	ctx := context.Background()

	server, cleanup, err := internal.NewServer(ctx, cfg)
	if err != nil {
		log.Fatalf("failed to create auth server: %v", err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("FrameVerse Auth server listening on :%s", cfg.Port)
		if err := server.ListenAndServe(); err != nil {
			log.Printf("server stopped: %v", err)
		}
	}()

	<-stop
	log.Println("shutting down FrameVerse Auth server...")

	if err := server.Shutdown(context.Background()); err != nil {
		log.Printf("server shutdown error: %v", err)
	}

	if err := cleanup(); err != nil {
		log.Printf("cleanup error: %v", err)
	}
}
