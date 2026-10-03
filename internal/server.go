package internal

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/PratSins/FrameVerse-Auth/config"
	"github.com/PratSins/FrameVerse-Auth/internal/auth"
	"github.com/PratSins/FrameVerse-Auth/internal/middleware"
	"github.com/PratSins/FrameVerse-Auth/pkg/jwt"
	"github.com/PratSins/FrameVerse-Auth/pkg/postgres"
	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
)

func NewServer(ctx context.Context, cfg *config.Config) (*http.Server, func() error, error) {
	// 1. Initialize PostgreSQL Connection Pool
	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	// 2. Run Database Auto-migrations
	if err := postgres.AutoMigrate(ctx, pool); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("database automigration failed: %w", err)
	}

	// 3. Initialize RS256 JWT Token Manager
	tokenManager, err := jwt.NewTokenManager(
		cfg.RSAPrivateKeyPath,
		cfg.RSAPublicKeyPath,
		cfg.RSAPrivateKeyPEM,
		cfg.RSAPublicKeyPEM,
	)
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("failed to initialize token manager: %w", err)
	}

	// 4. Initialize Dependency Layers
	authDAO := auth.NewDAO(pool)
	authService := auth.NewService(
		authDAO,
		tokenManager,
		cfg.AccessTokenTTLMinutes,
		cfg.RefreshTokenTTLDays,
	)
	authController := auth.NewController(authService, tokenManager)

	// 5. Setup Router and Middlewares
	r := chi.NewRouter()
	r.Use(chiMiddleware.Logger)
	r.Use(chiMiddleware.Recoverer)

	// CORS Middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// 6. Mount Routes
	authGuard := middleware.AuthGuard(tokenManager)
	authController.MountRoutes(r, authGuard)

	// Health Check Route
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"frameverse-auth"}`))
	})
	r.Get("/api/v1/auth/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"frameverse-auth"}`))
	})

	server := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	cleanup := func() error {
		log.Println("Closing PostgreSQL connection pool...")
		pool.Close()
		return nil
	}

	return server, cleanup, nil
}
