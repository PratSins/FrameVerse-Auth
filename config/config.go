package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	Port                  string
	DatabaseURL           string
	RSAPrivateKeyPath     string
	RSAPublicKeyPath      string
	RSAPrivateKeyPEM      string
	RSAPublicKeyPEM       string
	AccessTokenTTLMinutes int
	RefreshTokenTTLDays   int
	Environment           string
}

func Load() *Config {
	env := getEnv("ENVIRONMENT", "development")
	dbURL := getEnv("DATABASE_URL", "")

	// Fail-fast in production if database URL is missing
	if dbURL == "" {
		if env == "production" {
			log.Fatal("FATAL: DATABASE_URL environment variable is required in production mode")
		}
		// Safe fallback for local development only
		dbURL = "postgres://postgres:postgres@localhost:5432/frameverse_auth?sslmode=disable"
	}

	return &Config{
		Port:                  getEnv("PORT", "8081"),
		DatabaseURL:           dbURL,
		RSAPrivateKeyPath:     getEnv("RSA_PRIVATE_KEY_PATH", ""),
		RSAPublicKeyPath:      getEnv("RSA_PUBLIC_KEY_PATH", ""),
		RSAPrivateKeyPEM:      getEnv("RSA_PRIVATE_KEY_PEM", ""),
		RSAPublicKeyPEM:       getEnv("RSA_PUBLIC_KEY_PEM", ""),
		AccessTokenTTLMinutes: getEnvAsInt("ACCESS_TOKEN_TTL_MINUTES", 15),
		RefreshTokenTTLDays:   getEnvAsInt("REFRESH_TOKEN_TTL_DAYS", 7),
		Environment:           env,
	}
}

func getEnv(key, defaultVal string) string {
	if val, exists := os.LookupEnv(key); exists && val != "" {
		return val
	}
	return defaultVal
}

func getEnvAsInt(key string, defaultVal int) int {
	valStr := getEnv(key, "")
	if val, err := strconv.Atoi(valStr); err == nil {
		return val
	}
	return defaultVal
}
