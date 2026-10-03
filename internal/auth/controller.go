package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/PratSins/FrameVerse-Auth/internal/middleware"
	"github.com/PratSins/FrameVerse-Auth/pkg/jwt"
	"github.com/go-chi/chi/v5"
)

type Controller struct {
	service      *Service
	tokenManager *jwt.TokenManager
}

func NewController(service *Service, tokenManager *jwt.TokenManager) *Controller {
	return &Controller{
		service:      service,
		tokenManager: tokenManager,
	}
}

func (c *Controller) MountRoutes(r chi.Router, authGuard func(http.Handler) http.Handler) {
	// Public JWKS discovery endpoint
	r.Get("/.well-known/jwks.json", c.GetJWKS)

	// Auth API group
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/register", c.Register)
		r.Post("/login", c.Login)
		r.Post("/refresh", c.Refresh)
		r.Post("/logout", c.Logout)

		// Protected endpoints
		r.Group(func(r chi.Router) {
			r.Use(authGuard)
			r.Get("/me", c.GetMe)
		})
	})
}

func (c *Controller) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userAgent := r.UserAgent()
	ip := getClientIP(r)

	resp, err := c.service.Register(r.Context(), &req, userAgent, ip)
	if err != nil {
		if errors.Is(err, ErrInvalidEmail) || errors.Is(err, ErrWeakPassword) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, ErrUserAlreadyExists) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to register user: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

func (c *Controller) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userAgent := r.UserAgent()
	ip := getClientIP(r)

	resp, err := c.service.Login(r.Context(), &req, userAgent, ip)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to login: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (c *Controller) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	userAgent := r.UserAgent()
	ip := getClientIP(r)

	resp, err := c.service.Refresh(r.Context(), &req, userAgent, ip)
	if err != nil {
		if errors.Is(err, ErrInvalidRefreshToken) {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to refresh token: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (c *Controller) Logout(w http.ResponseWriter, r *http.Request) {
	var req LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := c.service.Logout(r.Context(), &req); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to logout: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
}

func (c *Controller) GetMe(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := c.service.GetMe(r.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get user: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, user)
}

func (c *Controller) GetJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := c.tokenManager.GetJWKS()
	writeJSON(w, http.StatusOK, jwks)
}

func writeJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, map[string]string{"error": message})
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return r.RemoteAddr
}
