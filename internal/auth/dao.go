package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrUserAlreadyExists    = errors.New("user with this email already exists")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
)

type DAO struct {
	pool *pgxpool.Pool
}

func NewDAO(pool *pgxpool.Pool) *DAO {
	return &DAO{
		pool: pool,
	}
}

func (d *DAO) CreateUser(ctx context.Context, user *User) error {
	query := `
		INSERT INTO users (email, password_hash, full_name, avatar_url, auth_provider, provider_id, is_verified, tier, credits)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at;
	`

	err := d.pool.QueryRow(
		ctx,
		query,
		user.Email,
		user.PasswordHash,
		user.FullName,
		user.AvatarURL,
		user.AuthProvider,
		user.ProviderID,
		user.IsVerified,
		user.Tier,
		user.Credits,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if isUniqueViolation(err) {
			return ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to insert user: %w", err)
	}

	return nil
}

func (d *DAO) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, email, password_hash, full_name, avatar_url, auth_provider, provider_id, is_verified, tier, credits, created_at, updated_at
		FROM users
		WHERE email = $1;
	`

	var user User
	err := d.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&user.AvatarURL,
		&user.AuthProvider,
		&user.ProviderID,
		&user.IsVerified,
		&user.Tier,
		&user.Credits,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

func (d *DAO) GetUserByID(ctx context.Context, id string) (*User, error) {
	query := `
		SELECT id, email, password_hash, full_name, avatar_url, auth_provider, provider_id, is_verified, tier, credits, created_at, updated_at
		FROM users
		WHERE id = $1;
	`

	var user User
	err := d.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&user.AvatarURL,
		&user.AuthProvider,
		&user.ProviderID,
		&user.IsVerified,
		&user.Tier,
		&user.Credits,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}

	return &user, nil
}

func (d *DAO) CreateRefreshToken(ctx context.Context, token *RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (user_id, token_hash, user_agent, ip_address, is_revoked, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at;
	`

	err := d.pool.QueryRow(
		ctx,
		query,
		token.UserID,
		token.TokenHash,
		token.UserAgent,
		token.IPAddress,
		token.IsRevoked,
		token.ExpiresAt,
	).Scan(&token.ID, &token.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to insert refresh token: %w", err)
	}

	return nil
}

func (d *DAO) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, user_agent, ip_address, is_revoked, expires_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1;
	`

	var token RefreshToken
	err := d.pool.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.UserAgent,
		&token.IPAddress,
		&token.IsRevoked,
		&token.ExpiresAt,
		&token.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	return &token, nil
}

func (d *DAO) RevokeRefreshToken(ctx context.Context, id string) error {
	query := `
		UPDATE refresh_tokens
		SET is_revoked = TRUE
		WHERE id = $1;
	`

	_, err := d.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	return nil
}

func (d *DAO) RevokeAllUserRefreshTokens(ctx context.Context, userID string) error {
	query := `
		UPDATE refresh_tokens
		SET is_revoked = TRUE
		WHERE user_id = $1 AND is_revoked = FALSE;
	`

	_, err := d.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke user refresh tokens: %w", err)
	}

	return nil
}

func isUniqueViolation(err error) bool {
	// Standard PostgreSQL unique constraint violation error code is 23505
	return err != nil && (err.Error() == "ERROR: duplicate key value violates unique constraint" ||
		fmt.Sprintf("%v", err) != "")
}
