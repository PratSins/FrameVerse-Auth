package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/PratSins/FrameVerse-Auth/pkg/jwt"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials  = errors.New("invalid email or password")
	ErrInvalidEmail        = errors.New("invalid email address")
	ErrWeakPassword        = errors.New("password must be at least 8 characters long")
	ErrInvalidRefreshToken = errors.New("invalid or expired refresh token")
)

type Service struct {
	dao                   *DAO
	tokenManager          *jwt.TokenManager
	accessTokenTTLMinutes int
	refreshTokenTTLDays   int
}

func NewService(
	dao *DAO,
	tokenManager *jwt.TokenManager,
	accessTokenTTLMinutes int,
	refreshTokenTTLDays int,
) *Service {
	return &Service{
		dao:                   dao,
		tokenManager:          tokenManager,
		accessTokenTTLMinutes: accessTokenTTLMinutes,
		refreshTokenTTLDays:   refreshTokenTTLDays,
	}
}

func (s *Service) Register(ctx context.Context, req *RegisterRequest, userAgent, ip string) (*AuthResponse, error) {
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, ErrInvalidEmail
	}

	if len(req.Password) < 8 {
		return nil, ErrWeakPassword
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	passwordHashStr := string(hashedPassword)
	user := &User{
		Email:        email,
		PasswordHash: &passwordHashStr,
		FullName:     strings.TrimSpace(req.FullName),
		AuthProvider: "local",
		IsVerified:   false,
		Tier:         "free",
		Credits:      10,
	}

	if err := s.dao.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return s.issueTokens(ctx, user, userAgent, ip)
}

func (s *Service) Login(ctx context.Context, req *LoginRequest, userAgent, ip string) (*AuthResponse, error) {
	email := strings.TrimSpace(strings.ToLower(req.Email))
	user, err := s.dao.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if user.PasswordHash == nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return s.issueTokens(ctx, user, userAgent, ip)
}

func (s *Service) Refresh(ctx context.Context, req *RefreshRequest, userAgent, ip string) (*AuthResponse, error) {
	if strings.TrimSpace(req.RefreshToken) == "" {
		return nil, ErrInvalidRefreshToken
	}

	tokenHash := hashToken(req.RefreshToken)
	storedToken, err := s.dao.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}

	if storedToken.IsRevoked || time.Now().After(storedToken.ExpiresAt) {
		// Automatic security measure: if a revoked token is replayed, revoke all user tokens
		if storedToken.IsRevoked {
			_ = s.dao.RevokeAllUserRefreshTokens(ctx, storedToken.UserID)
		}
		return nil, ErrInvalidRefreshToken
	}

	// Token rotation: Revoke used refresh token
	if err := s.dao.RevokeRefreshToken(ctx, storedToken.ID); err != nil {
		return nil, err
	}

	user, err := s.dao.GetUserByID(ctx, storedToken.UserID)
	if err != nil {
		return nil, err
	}

	return s.issueTokens(ctx, user, userAgent, ip)
}

func (s *Service) Logout(ctx context.Context, req *LogoutRequest) error {
	if strings.TrimSpace(req.RefreshToken) == "" {
		return nil
	}

	tokenHash := hashToken(req.RefreshToken)
	storedToken, err := s.dao.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil // idempotent logout
	}

	return s.dao.RevokeRefreshToken(ctx, storedToken.ID)
}

func (s *Service) GetMe(ctx context.Context, userID string) (*UserResponse, error) {
	user, err := s.dao.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	resp := user.ToResponse()
	return &resp, nil
}

func (s *Service) issueTokens(ctx context.Context, user *User, userAgent, ip string) (*AuthResponse, error) {
	accessToken, err := s.tokenManager.GenerateAccessToken(user.ID, user.Email, user.Tier, s.accessTokenTTLMinutes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	rawRefreshToken, err := generateSecureRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	refreshTokenHash := hashToken(rawRefreshToken)
	refreshTokenRecord := &RefreshToken{
		UserID:    user.ID,
		TokenHash: refreshTokenHash,
		UserAgent: userAgent,
		IPAddress: ip,
		IsRevoked: false,
		ExpiresAt: time.Now().Add(time.Duration(s.refreshTokenTTLDays) * 24 * time.Hour),
	}

	if err := s.dao.CreateRefreshToken(ctx, refreshTokenRecord); err != nil {
		return nil, err
	}

	return &AuthResponse{
		User: user.ToResponse(),
		Tokens: TokenPair{
			AccessToken:  accessToken,
			RefreshToken: rawRefreshToken,
			ExpiresIn:    s.accessTokenTTLMinutes * 60,
			TokenType:    "Bearer",
		},
	}, nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func generateSecureRandomString(byteLength int) (string, error) {
	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
