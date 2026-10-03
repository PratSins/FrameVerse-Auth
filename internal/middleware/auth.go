package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/PratSins/FrameVerse-Auth/pkg/jwt"
)

type contextKey string

const (
	UserIDContextKey contextKey = "user_id"
	EmailContextKey  contextKey = "email"
	TierContextKey   contextKey = "tier"
)

func AuthGuard(tokenManager *jwt.TokenManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				http.Error(w, `{"error":"invalid authorization header format"}`, http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]
			claims, err := tokenManager.ValidateAccessToken(tokenString)
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserIDContextKey, claims.UserID)
			ctx = context.WithValue(ctx, EmailContextKey, claims.Email)
			ctx = context.WithValue(ctx, TierContextKey, claims.Tier)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetUserID(ctx context.Context) string {
	if val, ok := ctx.Value(UserIDContextKey).(string); ok {
		return val
	}
	return ""
}

func GetEmail(ctx context.Context) string {
	if val, ok := ctx.Value(EmailContextKey).(string); ok {
		return val
	}
	return ""
}
