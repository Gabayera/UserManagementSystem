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

func makeUser(email string) *domain.User {
	now := time.Now().UTC()
	return &domain.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: "test-hash",
		FullName:     "Test User",
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func TestPGUserRepo_CreateAndGetByID(t *testing.T) {
	resetUserTables(t, testPool)
	ctx := context.Background()
	repo := NewPGUserRepo()

	u := makeUser("alice@example.com")
	if err := repo.Create(ctx, testPool, u); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.GetByID(ctx, testPool, u.ID)
	requireNoErr(t, err)
	if got.Email != "alice@example.com" || got.FullName != "Test User" {
		t.Fatalf("got=%+v", got)
	}
}

func TestPGUserRepo_GetByEmail_CaseInsensitive(t *testing.T) {
	resetUserTables(t, testPool)
	ctx := context.Background()
	repo := NewPGUserRepo()

	u := makeUser("bob@example.com")
	requireNoErr(t, repo.Create(ctx, testPool, u))

	// CITEXT: uppercase lookup must find the row.
	got, err := repo.GetByEmail(ctx, testPool, "BOB@EXAMPLE.COM")
	requireNoErr(t, err)
	if got.ID != u.ID {
		t.Fatalf("wrong user")
	}
}

func TestPGUserRepo_Create_DuplicateEmail_ErrConflict(t *testing.T) {
	resetUserTables(t, testPool)
	ctx := context.Background()
	repo := NewPGUserRepo()

	requireNoErr(t, repo.Create(ctx, testPool, makeUser("dup@example.com")))

	err := repo.Create(ctx, testPool, makeUser("dup@example.com"))
	if !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("err=%v want ErrConflict", err)
	}
}

func TestPGUserRepo_GetByID_SoftDeleted_ReturnsNotFound(t *testing.T) {
	resetUserTables(t, testPool)
	ctx := context.Background()
	repo := NewPGUserRepo()

	u := makeUser("gone@example.com")
	requireNoErr(t, repo.Create(ctx, testPool, u))
	requireNoErr(t, repo.SoftDelete(ctx, testPool, u.ID))

	_, err := repo.GetByID(ctx, testPool, u.ID)
	if !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("err=%v want ErrNotFound (soft-deleted row must be invisible)", err)
	}

	// But the row must still exist in the DB (soft delete, not hard).
	var count int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, u.ID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("count=%d, soft-deleted row should still be present", count)
	}
}

func TestPGUserRepo_Update_MissingID_ReturnsNotFound(t *testing.T) {
	resetUserTables(t, testPool)
	ctx := context.Background()
	repo := NewPGUserRepo()

	err := repo.Update(ctx, testPool, &domain.User{ID: uuid.New(), FullName: "ghost"})
	if !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("err=%v want ErrNotFound", err)
	}
}

func TestPGUserRepo_SetActive_UpdatesFlag(t *testing.T) {
	resetUserTables(t, testPool)
	ctx := context.Background()
	repo := NewPGUserRepo()

	u := makeUser("active@example.com")
	requireNoErr(t, repo.Create(ctx, testPool, u))

	requireNoErr(t, repo.SetActive(ctx, testPool, u.ID, false))
	got, _ := repo.GetByID(ctx, testPool, u.ID)
	if got.IsActive {
		t.Fatalf("expected inactive")
	}

	requireNoErr(t, repo.SetActive(ctx, testPool, u.ID, true))
	got, _ = repo.GetByID(ctx, testPool, u.ID)
	if !got.IsActive {
		t.Fatalf("expected active")
	}
}

func TestPGUserRepo_List_Pagination(t *testing.T) {
	resetUserTables(t, testPool)
	ctx := context.Background()
	repo := NewPGUserRepo()

	for i := 0; i < 3; i++ {
		requireNoErr(t, repo.Create(ctx, testPool, makeUser("u"+string(rune('a'+i))+"@example.com")))
	}

	users, total, err := repo.List(ctx, testPool, 2, 0)
	requireNoErr(t, err)
	if total != 3 {
		t.Fatalf("total=%d want 3", total)
	}
	if len(users) != 2 {
		t.Fatalf("len(users)=%d want 2", len(users))
	}
}

func TestPGUserRepo_AssignRole_Idempotent(t *testing.T) {
	resetUserTables(t, testPool)
	ctx := context.Background()
	repo := NewPGUserRepo()

	u := makeUser("assign@example.com")
	requireNoErr(t, repo.Create(ctx, testPool, u))

	// Look up the seeded "user" role.
	roleRepo := NewPGRoleRepo()
	userRole, err := roleRepo.GetByName(ctx, testPool, "user")
	requireNoErr(t, err)

	requireNoErr(t, repo.AssignRole(ctx, testPool, u.ID, userRole.ID))
	// Second call must not error.
	if err := repo.AssignRole(ctx, testPool, u.ID, userRole.ID); err != nil {
		t.Fatalf("second assign should be idempotent: %v", err)
	}

	roles, err := repo.RolesForUser(ctx, testPool, u.ID)
	requireNoErr(t, err)
	if len(roles) != 1 {
		t.Fatalf("roles=%d want 1", len(roles))
	}
}
