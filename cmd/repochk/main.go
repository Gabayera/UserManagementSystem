package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/domain"
	"UserManagementSystem/internal/repository"
)

// Deterministic IDs so cleanup is trivial and reruns are idempotent.
var (
	userA = uuid.MustParse("aaaa0000-0000-0000-0000-000000000001")
	userB = uuid.MustParse("aaaa0000-0000-0000-0000-000000000002")
	userC = uuid.MustParse("aaaa0000-0000-0000-0000-000000000003") // tx rollback victim
	userD = uuid.MustParse("aaaa0000-0000-0000-0000-000000000004") // tx commit survivor

	userRoleID   = uuid.MustParse("00000000-0000-4000-8000-000000000003") // seeded "user" role
	permUserRead = "user.read"                                            // seeded permission

	tokenID    = uuid.MustParse("bbbb0000-0000-0000-0000-000000000001")
	auditLogID = uuid.MustParse("cccc0000-0000-0000-0000-000000000001")
)

type env struct {
	pool *pgxpool.Pool

	users     *repository.PGUserRepo
	roles     *repository.PGRoleRepo
	perms     *repository.PGPermissionRepo
	tokens    *repository.PGRefreshTokenRepo
	auditLogs *repository.PGAuditLogRepo
}

func main() {
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	e := &env{
		pool:      pool,
		users:     repository.NewPGUserRepo(),
		roles:     repository.NewPGRoleRepo(),
		perms:     repository.NewPGPermissionRepo(),
		tokens:    repository.NewPGRefreshTokenRepo(),
		auditLogs: repository.NewPGAuditLogRepo(),
	}

	if err := cleanup(ctx, e); err != nil {
		log.Fatalf("cleanup: %v", err)
	}
	defer func() {
		if err := cleanup(context.Background(), e); err != nil {
			fmt.Println("CLEANUP FAILED:", err)
		}
	}()

	steps := []struct {
		name string
		fn   func(context.Context, *env) error
	}{
		{"ex01_create_and_read", ex01},
		{"ex02_duplicate_email", ex02},
		{"ex03_get_missing", ex03},
		{"ex04_list_paginated", ex04},
		{"ex05_assign_role", ex05},
		{"ex06_permissions_for_user", ex06},
		{"ex07_update_missing", ex07},
		{"ex08_tx_rollback", ex08},
		{"ex09_tx_commit", ex09},
		{"ex10_soft_delete_hides", ex10},
		{"ex11_refresh_reuse_detected", ex11},
		{"ex12_audit_log_roundtrip", ex12},
	}

	for _, s := range steps {
		fmt.Printf("=== %s ===\n", s.name)
		if err := s.fn(ctx, e); err != nil {
			log.Fatalf("%s: %v", s.name, err)
		}
	}
	fmt.Println("ALL EXERCISES PASSED")
}

func cleanup(ctx context.Context, e *env) error {
	// Deleting users cascades to user_roles and refresh_tokens (ON DELETE CASCADE).
	// audit_logs.actor_user_id is SET NULL, so explicitly delete test audit rows
	// by primary key first.
	if _, err := e.pool.Exec(ctx, `DELETE FROM audit_logs WHERE id = $1`, auditLogID); err != nil {
		return err
	}
	if _, err := e.pool.Exec(ctx,
		`DELETE FROM users WHERE id = ANY($1::uuid[])`,
		[]uuid.UUID{userA, userB, userC, userD},
	); err != nil {
		return err
	}
	return nil
}

// ---------- exercises ----------

func ex01(ctx context.Context, e *env) error {
	u := &domain.User{
		ID:           userA,
		Email:        "Alice@Example.com", // CITEXT: will store lowercased
		PasswordHash: "hash-alice",
		FullName:     "Alice",
		IsActive:     true,
	}
	if err := e.users.Create(ctx, e.pool, u); err != nil {
		return err
	}
	gotByID, err := e.users.GetByID(ctx, e.pool, userA)
	if err != nil {
		return err
	}
	gotByEmail, err := e.users.GetByEmail(ctx, e.pool, "alice@example.com")
	if err != nil {
		return err
	}
	if gotByID.ID != gotByEmail.ID || gotByID.ID != userA {
		return fmt.Errorf("ID mismatch")
	}
	fmt.Printf("created + read: id=%s email=%s active=%v\n", gotByID.ID, gotByID.Email, gotByID.IsActive)
	return nil
}

func ex02(ctx context.Context, e *env) error {
	dup := &domain.User{
		ID:           userB,
		Email:        "alice@example.com", // same email, different case
		PasswordHash: "hash-dup",
		FullName:     "Dup",
		IsActive:     true,
	}
	err := e.users.Create(ctx, e.pool, dup)
	if !errors.Is(err, apperr.ErrConflict) {
		return fmt.Errorf("expected ErrConflict, got %v", err)
	}
	fmt.Println("duplicate: errors.Is ErrConflict =", true)
	return nil
}

func ex03(ctx context.Context, e *env) error {
	_, err := e.users.GetByID(ctx, e.pool, uuid.New())
	if !errors.Is(err, apperr.ErrNotFound) {
		return fmt.Errorf("expected ErrNotFound, got %v", err)
	}
	fmt.Println("missing: errors.Is ErrNotFound =", true)
	return nil
}

func ex04(ctx context.Context, e *env) error {
	users, total, err := e.users.List(ctx, e.pool, 10, 0)
	if err != nil {
		return err
	}
	if total < 1 || len(users) < 1 {
		return fmt.Errorf("expected at least 1 user, got len=%d total=%d", len(users), total)
	}
	fmt.Printf("list: len=%d total=%d\n", len(users), total)
	return nil
}

func ex05(ctx context.Context, e *env) error {
	if err := e.users.AssignRole(ctx, e.pool, userA, userRoleID); err != nil {
		return err
	}
	// idempotency
	if err := e.users.AssignRole(ctx, e.pool, userA, userRoleID); err != nil {
		return fmt.Errorf("re-assign should be idempotent: %w", err)
	}
	roles, err := e.users.RolesForUser(ctx, e.pool, userA)
	if err != nil {
		return err
	}
	if len(roles) != 1 || roles[0].Name != "user" {
		return fmt.Errorf("expected 1 role 'user', got %v", roleNames(roles))
	}
	fmt.Println("assign role: ok, roles =", roleNames(roles))
	return nil
}

func ex06(ctx context.Context, e *env) error {
	perms, err := e.users.PermissionsForUser(ctx, e.pool, userA)
	if err != nil {
		return err
	}
	if len(perms) != 1 || perms[0].Code != permUserRead {
		return fmt.Errorf("expected [%s], got %v", permUserRead, permCodes(perms))
	}
	fmt.Println("permissions:", permCodes(perms))
	return nil
}

func ex07(ctx context.Context, e *env) error {
	ghost := &domain.User{ID: uuid.New(), FullName: "ghost"}
	err := e.users.Update(ctx, e.pool, ghost)
	if !errors.Is(err, apperr.ErrNotFound) {
		return fmt.Errorf("expected ErrNotFound, got %v", err)
	}
	fmt.Println("update missing: errors.Is ErrNotFound =", true)
	return nil
}

func ex08(ctx context.Context, e *env) error {
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return err
	}
	// NOTE: Rollback after explicit Rollback returns ErrTxClosed — ignored.
	defer func() { _ = tx.Rollback(ctx) }()

	u := &domain.User{
		ID: userC, Email: "c@example.com", PasswordHash: "h", FullName: "C", IsActive: true,
	}
	if err := e.users.Create(ctx, tx, u); err != nil {
		return err
	}
	if err := tx.Rollback(ctx); err != nil {
		return err
	}
	_, err = e.users.GetByID(ctx, e.pool, userC)
	if !errors.Is(err, apperr.ErrNotFound) {
		return fmt.Errorf("expected rollback (ErrNotFound), got %v", err)
	}
	fmt.Println("after rollback: row absent")
	return nil
}

func ex09(ctx context.Context, e *env) error {
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	u := &domain.User{
		ID: userD, Email: "d@example.com", PasswordHash: "h", FullName: "D", IsActive: true,
	}
	if err := e.users.Create(ctx, tx, u); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	got, err := e.users.GetByID(ctx, e.pool, userD)
	if err != nil {
		return fmt.Errorf("expected commit, got %v", err)
	}
	fmt.Println("after commit: row present, id =", got.ID)
	return nil
}

func ex10(ctx context.Context, e *env) error {
	if err := e.users.SoftDelete(ctx, e.pool, userD); err != nil {
		return err
	}
	_, err := e.users.GetByID(ctx, e.pool, userD)
	if !errors.Is(err, apperr.ErrNotFound) {
		return fmt.Errorf("expected ErrNotFound after soft-delete, got %v", err)
	}
	fmt.Println("soft-delete: hidden from GetByID")
	return nil
}

func ex11(ctx context.Context, e *env) error {
	familyID := uuid.New()
	hash := "0000000000000000000000000000000000000000000000000000000000000001"
	orig := &domain.RefreshToken{
		ID:        tokenID,
		UserID:    userA,
		TokenHash: hash,
		FamilyID:  familyID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if err := e.tokens.Create(ctx, e.pool, orig); err != nil {
		return err
	}

	// Rotate once — should succeed.
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return err
	}
	first := &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    userA,
		TokenHash: hash[:62] + "02",
		FamilyID:  familyID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if err := e.tokens.Rotate(ctx, tx, tokenID, first); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("first rotate should succeed: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	// Second rotate on the now-revoked original — should fail with ErrNotFound.
	tx2, err := e.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx2.Rollback(ctx) }()
	second := &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    userA,
		TokenHash: hash[:62] + "03",
		FamilyID:  familyID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	rotErr := e.tokens.Rotate(ctx, tx2, tokenID, second)
	if !errors.Is(rotErr, apperr.ErrNotFound) {
		return fmt.Errorf("expected ErrNotFound on reuse, got %v", rotErr)
	}
	fmt.Println("reuse: second rotate on revoked token returns ErrNotFound =", true)
	return nil
}

func ex12(ctx context.Context, e *env) error {
	ip := "203.0.113.5"
	reqID := "req-test-0001"
	entry := &domain.AuditLog{
		ID:          auditLogID,
		ActorUserID: &userA,
		Action:      "user.read.test",
		EntityType:  strPtr("user"),
		EntityID:    &userA,
		Metadata:    map[string]any{"k": "v", "n": float64(42)},
		IPAddress:   &ip,
		RequestID:   &reqID,
	}
	if err := e.auditLogs.Create(ctx, e.pool, entry); err != nil {
		return err
	}
	byActor, err := e.auditLogs.ListByActor(ctx, e.pool, userA, 10, 0)
	if err != nil {
		return err
	}
	byEntity, err := e.auditLogs.ListByEntity(ctx, e.pool, "user", userA, 10, 0)
	if err != nil {
		return err
	}
	if len(byActor) < 1 || len(byEntity) < 1 {
		return fmt.Errorf("audit list: actor=%d entity=%d", len(byActor), len(byEntity))
	}
	got := byActor[0]
	if got.Metadata["k"] != "v" || got.Metadata["n"] != float64(42) {
		return fmt.Errorf("metadata not round-tripped: %#v", got.Metadata)
	}
	if got.IPAddress == nil {
		return fmt.Errorf("ip not round-tripped: nil")
	}
	if *got.IPAddress != ip {
		return fmt.Errorf("ip not round-tripped: got=%q want=%q", *got.IPAddress, ip)
	}
	fmt.Printf("audit: actor=%d entity=%d metadata=%v ip=%s\n",
		len(byActor), len(byEntity), got.Metadata, *got.IPAddress)
	return nil
}

func roleNames(rs []*domain.Role) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}

func permCodes(ps []*domain.Permission) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Code)
	}
	return out
}

func strPtr(s string) *string { return &s }

// ensure pgx is used even if future edits drop direct references.
var _ = pgx.ErrNoRows
