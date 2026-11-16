package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/domain"
)

func seedUser(t *testing.T, repo UserRepository, email string) *domain.User {
	t.Helper()
	u := makeUser(email)
	requireNoErr(t, repo.Create(context.Background(), testPool, u))
	return u
}

func makeToken(userID uuid.UUID, familyID uuid.UUID, hash string) *domain.RefreshToken {
	return &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: hash,
		FamilyID:  familyID,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
}

func TestPGRefreshTokenRepo_CreateAndGetByHash(t *testing.T) {
	resetUserTables(t, testPool)
	ctx := context.Background()
	users := NewPGUserRepo()
	tokens := NewPGRefreshTokenRepo()

	u := seedUser(t, users, "tok@example.com")
	tok := makeToken(u.ID, uuid.New(), "hash-abc")
	requireNoErr(t, tokens.Create(ctx, testPool, tok))

	got, err := tokens.GetByHash(ctx, testPool, "hash-abc")
	requireNoErr(t, err)
	if got.ID != tok.ID {
		t.Fatalf("wrong token")
	}
}

func TestPGRefreshTokenRepo_Rotate_HappyPath(t *testing.T) {
	resetUserTables(t, testPool)
	ctx := context.Background()
	users := NewPGUserRepo()
	tokens := NewPGRefreshTokenRepo()

	u := seedUser(t, users, "rot@example.com")
	family := uuid.New()
	old := makeToken(u.ID, family, "old-hash")
	requireNoErr(t, tokens.Create(ctx, testPool, old))

	tx, err := testPool.Begin(ctx)
	requireNoErr(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	newTok := makeToken(u.ID, family, "new-hash")
	requireNoErr(t, tokens.Rotate(ctx, tx, old.ID, newTok))
	requireNoErr(t, tx.Commit(ctx))

	// Old is revoked.
	var revokedAt *time.Time
	requireNoErr(t, testPool.QueryRow(ctx,
		`SELECT revoked_at FROM refresh_tokens WHERE id = $1`, old.ID).Scan(&revokedAt))
	if revokedAt == nil {
		t.Fatalf("old token should be revoked")
	}

	// New exists.
	got, err := tokens.GetByHash(ctx, testPool, "new-hash")
	requireNoErr(t, err)
	if got.ID != newTok.ID {
		t.Fatalf("new token not found")
	}
}

// Critical security property: a re-use of an already-revoked token must
// surface as ErrNotFound so the caller (AuthService) triggers family revoke.
func TestPGRefreshTokenRepo_Rotate_AlreadyRevoked_ReturnsNotFound(t *testing.T) {
	resetUserTables(t, testPool)
	ctx := context.Background()
	users := NewPGUserRepo()
	tokens := NewPGRefreshTokenRepo()

	u := seedUser(t, users, "reuse@example.com")
	family := uuid.New()
	old := makeToken(u.ID, family, "revoked-hash")
	requireNoErr(t, tokens.Create(ctx, testPool, old))
	requireNoErr(t, tokens.RevokeByID(ctx, testPool, old.ID))

	tx, err := testPool.Begin(ctx)
	requireNoErr(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	err = tokens.Rotate(ctx, tx, old.ID, makeToken(u.ID, family, "next-hash"))
	if !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("err=%v want ErrNotFound (reuse signal)", err)
	}
}

func TestPGRefreshTokenRepo_RevokeByFamily(t *testing.T) {
	resetUserTables(t, testPool)
	ctx := context.Background()
	users := NewPGUserRepo()
	tokens := NewPGRefreshTokenRepo()

	u := seedUser(t, users, "fam@example.com")
	family := uuid.New()
	requireNoErr(t, tokens.Create(ctx, testPool, makeToken(u.ID, family, "h1")))
	requireNoErr(t, tokens.Create(ctx, testPool, makeToken(u.ID, family, "h2")))
	requireNoErr(t, tokens.RevokeByFamily(ctx, testPool, family))

	var active int
	requireNoErr(t, testPool.QueryRow(ctx,
		`SELECT count(*) FROM refresh_tokens WHERE family_id = $1 AND revoked_at IS NULL`,
		family).Scan(&active))
	if active != 0 {
		t.Fatalf("active=%d want 0", active)
	}
}
