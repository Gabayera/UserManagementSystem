package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/domain"
)

type PGRefreshTokenRepo struct{}

func NewPGRefreshTokenRepo() *PGRefreshTokenRepo { return &PGRefreshTokenRepo{} }

var _ RefreshTokenRepository = (*PGRefreshTokenRepo)(nil)

const refreshTokenColumns = `id, user_id, token_hash, family_id, expires_at, revoked_at, replaced_by, user_agent, ip_address::text, created_at`

func scanRefreshToken(s interface{ Scan(dest ...any) error }) (*domain.RefreshToken, error) {
	var t domain.RefreshToken
	if err := s.Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.FamilyID, &t.ExpiresAt,
		&t.RevokedAt, &t.ReplacedBy, &t.UserAgent, &t.IPAddress, &t.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *PGRefreshTokenRepo) Create(ctx context.Context, q Querier, t *domain.RefreshToken) error {
	const sql = `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at, user_agent, ip_address)
	             VALUES ($1, $2, $3, $4, $5, $6, $7::inet)`
	_, err := q.Exec(ctx, sql, t.ID, t.UserID, t.TokenHash, t.FamilyID, t.ExpiresAt, t.UserAgent, t.IPAddress)
	return MapError(err)
}

func (r *PGRefreshTokenRepo) GetByHash(ctx context.Context, q Querier, hash string) (*domain.RefreshToken, error) {
	const sql = `SELECT ` + refreshTokenColumns + ` FROM refresh_tokens WHERE token_hash = $1`
	t, err := scanRefreshToken(q.QueryRow(ctx, sql, hash))
	if err != nil {
		return nil, MapError(err)
	}
	return t, nil
}

func (r *PGRefreshTokenRepo) RevokeByID(ctx context.Context, q Querier, id uuid.UUID) error {
	const sql = `UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`
	_, err := q.Exec(ctx, sql, id)
	return MapError(err)
}

func (r *PGRefreshTokenRepo) RevokeByFamily(ctx context.Context, q Querier, familyID uuid.UUID) error {
	const sql = `UPDATE refresh_tokens SET revoked_at = NOW() WHERE family_id = $1 AND revoked_at IS NULL`
	_, err := q.Exec(ctx, sql, familyID)
	return MapError(err)
}

func (r *PGRefreshTokenRepo) RevokeAllForUser(ctx context.Context, q Querier, userID uuid.UUID) error {
	const sql = `UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`
	_, err := q.Exec(ctx, sql, userID)
	return MapError(err)
}

// Rotate revokes the old token and inserts the new one atomically. The
// caller MUST pass a pgx.Tx; if the old row is already revoked (reuse), the
// UPDATE hits 0 rows and Rotate returns ErrNotFound, signalling the caller
// to trigger family revoke.
func (r *PGRefreshTokenRepo) Rotate(ctx context.Context, q Querier, oldID uuid.UUID, newToken *domain.RefreshToken) error {
	const revokeSQL = `UPDATE refresh_tokens
	                   SET revoked_at = NOW(), replaced_by = $2
	                   WHERE id = $1 AND revoked_at IS NULL`
	tag, err := q.Exec(ctx, revokeSQL, oldID, newToken.ID)
	if err != nil {
		return MapError(err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: refresh token already revoked", apperr.ErrNotFound)
	}

	const insertSQL = `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at, user_agent, ip_address)
	                   VALUES ($1, $2, $3, $4, $5, $6, $7::inet)`
	_, err = q.Exec(ctx, insertSQL,
		newToken.ID, newToken.UserID, newToken.TokenHash, newToken.FamilyID,
		newToken.ExpiresAt, newToken.UserAgent, newToken.IPAddress,
	)
	return MapError(err)
}
