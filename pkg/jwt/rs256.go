package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type CustomClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Tier   string `json:"tier"`
	jwt.RegisteredClaims
}

type TokenManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

func NewTokenManager(privKeyPath, pubKeyPath, privKeyPEM, pubKeyPEM string) (*TokenManager, error) {
	var privKey *rsa.PrivateKey
	var pubKey *rsa.PublicKey
	var err error

	if privKeyPEM != "" {
		privKey, err = parseRSAPrivateKeyFromPEM([]byte(privKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key from PEM env: %w", err)
		}
	} else if privKeyPath != "" {
		data, err := os.ReadFile(privKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file: %w", err)
		}
		privKey, err = parseRSAPrivateKeyFromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key from file: %w", err)
		}
	}

	if pubKeyPEM != "" {
		pubKey, err = parseRSAPublicKeyFromPEM([]byte(pubKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key from PEM env: %w", err)
		}
	} else if pubKeyPath != "" {
		data, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key file: %w", err)
		}
		pubKey, err = parseRSAPublicKeyFromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key from file: %w", err)
		}
	}

	// If no keys configured, generate an ephemeral RSA 2048-bit key pair
	if privKey == nil {
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral RSA key pair: %w", err)
		}
		pubKey = &privKey.PublicKey
	} else if pubKey == nil {
		pubKey = &privKey.PublicKey
	}

	return &TokenManager{
		privateKey: privKey,
		publicKey:  pubKey,
		keyID:      "frameverse-auth-key-1",
	}, nil
}

func (m *TokenManager) GenerateAccessToken(userID, email, tier string, ttlMinutes int) (string, error) {
	now := time.Now()
	claims := CustomClaims{
		UserID: userID,
		Email:  email,
		Tier:   tier,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "frameverse-auth",
			Subject:   userID,
			Audience:  jwt.ClaimStrings{"frameverse-api"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttlMinutes) * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.keyID

	signedToken, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return signedToken, nil
}

func (m *TokenManager) ValidateAccessToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

func (m *TokenManager) GetJWKS() map[string]interface{} {
	nBytes := m.publicKey.N.Bytes()
	eBytes := big.NewInt(int64(m.publicKey.E)).Bytes()

	key := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": m.keyID,
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}

	return map[string]interface{}{
		"keys": []map[string]interface{}{key},
	}
}

func parseRSAPrivateKeyFromPEM(keyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	if privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return privKey, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}

	privKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	return privKey, nil
}

func parseRSAPublicKeyFromPEM(keyData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	if pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pubKey, nil
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	pubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return pubKey, nil
}
