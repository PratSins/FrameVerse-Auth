package test

import (
	"testing"

	"github.com/PratSins/FrameVerse-Auth/pkg/jwt"
	"golang.org/x/crypto/bcrypt"
)

func TestTokenManager_GenerateAndValidate(t *testing.T) {
	manager, err := jwt.NewTokenManager("", "", "", "")
	if err != nil {
		t.Fatalf("failed to create TokenManager: %v", err)
	}

	userID := "user-12345"
	email := "test@example.com"
	tier := "pro"
	ttlMinutes := 15

	token, err := manager.GenerateAccessToken(userID, email, tier, ttlMinutes)
	if err != nil {
		t.Fatalf("failed to generate access token: %v", err)
	}

	if token == "" {
		t.Fatal("expected non-empty access token")
	}

	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("failed to validate access token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("expected UserID %s, got %s", userID, claims.UserID)
	}

	if claims.Email != email {
		t.Errorf("expected Email %s, got %s", email, claims.Email)
	}

	if claims.Tier != tier {
		t.Errorf("expected Tier %s, got %s", tier, claims.Tier)
	}
}

func TestTokenManager_GetJWKS(t *testing.T) {
	manager, err := jwt.NewTokenManager("", "", "", "")
	if err != nil {
		t.Fatalf("failed to create TokenManager: %v", err)
	}

	jwks := manager.GetJWKS()
	keys, ok := jwks["keys"].([]map[string]interface{})
	if !ok || len(keys) == 0 {
		t.Fatalf("expected non-empty JWKS keys list")
	}

	key := keys[0]
	if key["kty"] != "RSA" {
		t.Errorf("expected kty RSA, got %v", key["kty"])
	}
	if key["alg"] != "RS256" {
		t.Errorf("expected alg RS256, got %v", key["alg"])
	}
	if key["use"] != "sig" {
		t.Errorf("expected use sig, got %v", key["use"])
	}
	if key["n"] == nil || key["e"] == nil {
		t.Errorf("expected modulus n and exponent e in JWKS")
	}
}

func TestPasswordHashing(t *testing.T) {
	password := "SuperSecretPassword123!"

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		t.Errorf("password verification failed: %v", err)
	}

	if err := bcrypt.CompareHashAndPassword(hash, []byte("WrongPassword")); err == nil {
		t.Errorf("expected error on wrong password, got nil")
	}
}
