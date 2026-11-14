package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/config"
	"UserManagementSystem/internal/database"
	"UserManagementSystem/internal/domain"
	"UserManagementSystem/internal/repository"
	"UserManagementSystem/internal/service"
)

var (
	testUserID = uuid.MustParse("aaaa1111-0000-0000-0000-000000000001")
	testEmail  = "rbaccheck@example.com"
)

type env struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	roleSvc  *service.RoleService
	permSvc  *service.PermissionService
	resolver service.PermissionsResolver
	userRepo repository.UserRepository

	testUserID   uuid.UUID // deterministic for cleanup
	testRoleID   uuid.UUID
	testPermID   uuid.UUID
	editorRoleID uuid.UUID
	userRoleID   uuid.UUID
}

func main() {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	pool, err := database.NewPool(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()

	userRepo := repository.NewPGUserRepo()
	roleRepo := repository.NewPGRoleRepo()
	permRepo := repository.NewPGPermissionRepo()
	audit := service.NewNoopAudit()

	e := &env{
		ctx:      ctx,
		pool:     pool,
		roleSvc:  service.NewRoleService(pool, roleRepo, audit),
		permSvc:  service.NewPermissionService(pool, permRepo, audit),
		resolver: service.NewDBPermissionsResolver(pool, userRepo),
		userRepo: userRepo,
	}

	if err := cleanup(ctx, e); err != nil {
		log.Fatalf("cleanup: %v", err)
	}
	defer func() {
		if err := cleanup(context.Background(), e); err != nil {
			fmt.Println("CLEANUP FAILED:", err)
		}
	}()

	// Look up seeded roles for later reference.
	editor, err := roleRepo.GetByName(ctx, pool, "editor")
	if err != nil {
		log.Fatalf("lookup editor role (did you run Part 5 migrations?): %v", err)
	}
	e.editorRoleID = editor.ID

	user, err := roleRepo.GetByName(ctx, pool, "user")
	if err != nil {
		log.Fatalf("lookup user role: %v", err)
	}
	e.userRoleID = user.ID

	steps := []struct {
		name string
		fn   func(*env) error
	}{
		{"01 list seeded roles", ex01},
		{"02 list seeded permissions", ex02},
		{"03 create test_role", ex03},
		{"04 duplicate test_role", ex04},
		{"05 create test.read", ex05},
		{"06 duplicate test.read", ex06},
		{"07 create user + assign test_role", ex07},
		{"08 add test.read twice (idempotent)", ex08},
		{"09 resolver shows test.read", ex09},
		{"10 add user.read to test_role", ex10},
		{"11 resolver shows {test.read,user.read}", ex11},
		{"12 assign editor to user", ex12},
		{"13 resolver shows union", ex13},
		{"14 delete test.read while granted", ex14},
		{"15 remove test.read from test_role", ex15},
		{"16 resolver shows {user.read,user.update}", ex16},
		{"17 delete test.read", ex17},
		{"18 GetByCode test.read not found", ex18},
		{"19 soft-delete test_role while user in role", ex19},
		{"20 remove role, soft-delete, GetByID not found", ex20},
	}

	for _, s := range steps {
		fmt.Printf("=== %s ===\n", s.name)
		if err := s.fn(e); err != nil {
			log.Fatalf("%s: %v", s.name, err)
		}
	}
	fmt.Println("ALL EXERCISES PASSED")
}

func cleanup(ctx context.Context, e *env) error {
	// Delete audit rows first (FK SET NULL leaves orphans otherwise).
	if _, err := e.pool.Exec(ctx,
		`DELETE FROM audit_logs WHERE actor_user_id = $1 OR action LIKE 'role.%' OR action LIKE 'permission.%'`,
		testUserID); err != nil {
		return fmt.Errorf("cleanup audit_logs: %w", err)
	}
	if _, err := e.pool.Exec(ctx, `DELETE FROM users WHERE id = $1 OR email = $2`, testUserID, testEmail); err != nil {
		return fmt.Errorf("cleanup users: %w", err)
	}
	// Hard-delete test role and permission that may have been left behind.
	if _, err := e.pool.Exec(ctx,
		`DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE name = 'test_role')`); err != nil {
		return err
	}
	if _, err := e.pool.Exec(ctx,
		`DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE name = 'test_role')`); err != nil {
		return err
	}
	if _, err := e.pool.Exec(ctx, `DELETE FROM roles WHERE name = 'test_role'`); err != nil {
		return err
	}
	if _, err := e.pool.Exec(ctx,
		`DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code = 'test.read')`); err != nil {
		return err
	}
	if _, err := e.pool.Exec(ctx, `DELETE FROM permissions WHERE code = 'test.read'`); err != nil {
		return err
	}
	return nil
}

// ---------- helpers ----------

func permKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func exactly(m map[string]struct{}, want ...string) error {
	if len(m) != len(want) {
		return fmt.Errorf("got %v want %v", permKeys(m), want)
	}
	for _, c := range want {
		if _, ok := m[c]; !ok {
			return fmt.Errorf("got %v want %v (missing %q)", permKeys(m), want, c)
		}
	}
	return nil
}

// ---------- test cases ----------

func ex01(e *env) error {
	roles, total, err := e.roleSvc.List(e.ctx, 100, 0)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(roles))
	for _, r := range roles {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	want := []string{"admin", "editor", "user"}
	if total < 3 || len(names) < 3 {
		return fmt.Errorf("expected ≥3 roles, got total=%d names=%v", total, names)
	}
	for _, w := range want {
		found := false
		for _, n := range names {
			if n == w {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing seeded role %q in %v", w, names)
		}
	}
	fmt.Printf("roles: total=%d names=%v\n", total, names)
	return nil
}

func ex02(e *env) error {
	perms, total, err := e.permSvc.List(e.ctx, 100, 0)
	if err != nil {
		return err
	}
	if total < 12 {
		return fmt.Errorf("expected ≥12 permissions, got %d", total)
	}
	found := false
	for _, p := range perms {
		if p.Code == "user.read" {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("missing user.read permission")
	}
	fmt.Printf("permissions: total=%d\n", total)
	return nil
}

func ex03(e *env) error {
	role, err := e.roleSvc.Create(e.ctx, service.CreateRoleInput{Name: "test_role"})
	if err != nil {
		return err
	}
	e.testRoleID = role.ID
	fmt.Printf("created: id=%s name=%s\n", role.ID, role.Name)
	return nil
}

func ex04(e *env) error {
	_, err := e.roleSvc.Create(e.ctx, service.CreateRoleInput{Name: "test_role"})
	if !errors.Is(err, apperr.ErrConflict) {
		return fmt.Errorf("expected ErrConflict, got %v", err)
	}
	fmt.Println("duplicate role: ErrConflict")
	return nil
}

func ex05(e *env) error {
	p, err := e.permSvc.Create(e.ctx, service.CreatePermissionInput{Code: "test.read"})
	if err != nil {
		return err
	}
	e.testPermID = p.ID
	fmt.Printf("created permission: id=%s code=%s\n", p.ID, p.Code)
	return nil
}

func ex06(e *env) error {
	_, err := e.permSvc.Create(e.ctx, service.CreatePermissionInput{Code: "test.read"})
	if !errors.Is(err, apperr.ErrConflict) {
		return fmt.Errorf("expected ErrConflict, got %v", err)
	}
	fmt.Println("duplicate permission: ErrConflict")
	return nil
}

func ex07(e *env) error {
	u := &domain.User{
		ID:           testUserID,
		Email:        testEmail,
		PasswordHash: "not-used-by-rbaccheck",
		FullName:     "RBAC Check User",
		IsActive:     true,
	}
	if err := e.userRepo.Create(e.ctx, e.pool, u); err != nil {
		return err
	}
	if err := e.userRepo.AssignRole(e.ctx, e.pool, testUserID, e.testRoleID); err != nil {
		return err
	}
	roles, err := e.userRepo.RolesForUser(e.ctx, e.pool, testUserID)
	if err != nil {
		return err
	}
	if len(roles) != 1 || roles[0].Name != "test_role" {
		return fmt.Errorf("expected 1 role test_role, got %v", roles)
	}
	fmt.Println("user created, assigned test_role")
	return nil
}

func ex08(e *env) error {
	if err := e.roleSvc.AddPermission(e.ctx, e.testRoleID, e.testPermID, nil); err != nil {
		return err
	}
	if err := e.roleSvc.AddPermission(e.ctx, e.testRoleID, e.testPermID, nil); err != nil {
		return fmt.Errorf("second AddPermission should be idempotent: %w", err)
	}
	fmt.Println("AddPermission twice: idempotent")
	return nil
}

func ex09(e *env) error {
	perms, err := e.resolver.PermissionsForUser(e.ctx, testUserID)
	if err != nil {
		return err
	}
	if perms == nil {
		return fmt.Errorf("resolver returned nil map")
	}
	if err := exactly(perms, "test.read"); err != nil {
		return err
	}
	fmt.Printf("resolver: %v\n", permKeys(perms))
	return nil
}

func ex10(e *env) error {
	userRead, err := e.permSvc.GetByCode(e.ctx, "user.read")
	if err != nil {
		return err
	}
	return e.roleSvc.AddPermission(e.ctx, e.testRoleID, userRead.ID, nil)
}

func ex11(e *env) error {
	perms, err := e.resolver.PermissionsForUser(e.ctx, testUserID)
	if err != nil {
		return err
	}
	if err := exactly(perms, "test.read", "user.read"); err != nil {
		return err
	}
	fmt.Printf("resolver: %v\n", permKeys(perms))
	return nil
}

func ex12(e *env) error {
	if err := e.userRepo.AssignRole(e.ctx, e.pool, testUserID, e.editorRoleID); err != nil {
		return err
	}
	fmt.Println("assigned editor role")
	return nil
}

func ex13(e *env) error {
	perms, err := e.resolver.PermissionsForUser(e.ctx, testUserID)
	if err != nil {
		return err
	}
	if err := exactly(perms, "test.read", "user.read", "user.update"); err != nil {
		return err
	}
	fmt.Printf("resolver: %v\n", permKeys(perms))
	return nil
}

func ex14(e *env) error {
	err := e.permSvc.Delete(e.ctx, e.testPermID, nil)
	if !errors.Is(err, apperr.ErrConflict) {
		return fmt.Errorf("expected ErrConflict (still granted), got %v", err)
	}
	fmt.Println("delete while granted: ErrConflict")
	return nil
}

func ex15(e *env) error {
	if err := e.roleSvc.RemovePermission(e.ctx, e.testRoleID, e.testPermID, nil); err != nil {
		return err
	}
	fmt.Println("removed test.read from test_role")
	return nil
}

func ex16(e *env) error {
	perms, err := e.resolver.PermissionsForUser(e.ctx, testUserID)
	if err != nil {
		return err
	}
	if err := exactly(perms, "user.read", "user.update"); err != nil {
		return err
	}
	fmt.Printf("resolver: %v\n", permKeys(perms))
	return nil
}

func ex17(e *env) error {
	if err := e.permSvc.Delete(e.ctx, e.testPermID, nil); err != nil {
		return err
	}
	fmt.Println("test.read deleted")
	return nil
}

func ex18(e *env) error {
	_, err := e.permSvc.GetByCode(e.ctx, "test.read")
	if !errors.Is(err, apperr.ErrNotFound) {
		return fmt.Errorf("expected ErrNotFound, got %v", err)
	}
	fmt.Println("GetByCode test.read: ErrNotFound")
	return nil
}

func ex19(e *env) error {
	err := e.roleSvc.SoftDelete(e.ctx, e.testRoleID, nil)
	if !errors.Is(err, apperr.ErrConflict) {
		return fmt.Errorf("expected ErrConflict (user still in role), got %v", err)
	}
	fmt.Println("soft-delete while assigned: ErrConflict")
	return nil
}

func ex20(e *env) error {
	if err := e.userRepo.RemoveRole(e.ctx, e.pool, testUserID, e.testRoleID); err != nil {
		return err
	}
	if err := e.roleSvc.SoftDelete(e.ctx, e.testRoleID, nil); err != nil {
		return err
	}
	_, err := e.roleSvc.GetByID(e.ctx, e.testRoleID)
	if !errors.Is(err, apperr.ErrNotFound) {
		return fmt.Errorf("expected ErrNotFound after soft-delete, got %v", err)
	}
	fmt.Println("soft-delete succeeded, GetByID → ErrNotFound")
	return nil
}
