package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/config"
	"UserManagementSystem/internal/database"
	"UserManagementSystem/internal/repository"
	"UserManagementSystem/internal/security"
	"UserManagementSystem/internal/service"
)

const (
	testEmail = "authcheck@example.com"
	testPass  = "correct-horse-battery-staple"
)

var testUserID = uuid.MustParse("eeee0000-0000-0000-0000-000000000001")

type env struct {
	pool *pgxpool.Pool
	auth *service.AuthService
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

	hasher := security.NewPasswordHasher(cfg.Auth.MaxConcurrentHashes)
	jwtIssuer := security.NewJWTIssuer(cfg.Auth.JWTSecret, cfg.Auth.JWTIssuer, cfg.Auth.AccessTokenTTL)

	authSvc, err := service.NewAuthService(
		pool,
		repository.NewPGUserRepo(),
		repository.NewPGRefreshTokenRepo(),
		repository.NewPGRoleRepo(),
		hasher,
		jwtIssuer,
		service.NewNoopAudit(),
		cfg.Auth.AccessTokenTTL,
		cfg.Auth.RefreshTokenTTL,
	)
	if err != nil {
		log.Fatalf("auth svc: %v", err)
	}

	e := &env{pool: pool, auth: authSvc}

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
		{"ex01_register_happy", ex01},
		{"ex02_register_duplicate", ex02},
		{"ex03_password_hashed", ex03},
		{"ex04_login_correct", ex04},
		{"ex05_login_wrong_pass_timing", ex05},
		{"ex06_login_unknown_email_timing", ex06},
		{"ex07_login_inactive_user", ex07},
		{"ex08_refresh_rotates", ex08},
		{"ex09_old_token_revoked", ex09},
		{"ex10_reuse_detection", ex10},
		{"ex11_logout", ex11},
		{"ex12_logout_all", ex12},
		{"ex13_me_returns_roles_perms", ex13},
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
	_, err := e.pool.Exec(ctx,
		`DELETE FROM users WHERE email = $1 OR id = $2`,
		testEmail, testUserID,
	)
	return err
}

func ex01(ctx context.Context, e *env) error {
	u, err := e.auth.Register(ctx, service.RegisterInput{
		Email:    testEmail,
		Password: testPass,
		FullName: "Auth Check",
	})
	if err != nil {
		return err
	}
	if u.ID != testUserID {
		// The server generates its own UUID; record whatever it produced for
		// the rest of the exercises.
		testUserID = u.ID
	}
	fmt.Printf("registered: id=%s email=%s\n", u.ID, u.Email)
	return nil
}

func ex02(ctx context.Context, e *env) error {
	_, err := e.auth.Register(ctx, service.RegisterInput{
		Email:    testEmail,
		Password: testPass,
		FullName: "Dup",
	})
	if !errors.Is(err, apperr.ErrConflict) {
		return fmt.Errorf("expected ErrConflict, got %v", err)
	}
	fmt.Println("duplicate email: ErrConflict =", true)
	return nil
}

func ex03(ctx context.Context, e *env) error {
	var hash string
	if err := e.pool.QueryRow(ctx,
		`SELECT password_hash FROM users WHERE id = $1`, testUserID).Scan(&hash); err != nil {
		return err
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		return fmt.Errorf("unexpected hash: %q", hash)
	}
	fmt.Println("password hashed with argon2id PHC string")
	return nil
}

func ex04(ctx context.Context, e *env) error {
	pair, err := e.auth.Login(ctx,
		service.LoginInput{Email: testEmail, Password: testPass}, nil, nil)
	if err != nil {
		return err
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" || pair.ExpiresIn <= 0 {
		return fmt.Errorf("incomplete token pair")
	}
	fmt.Printf("login ok: expires_in=%d, refresh_len=%d\n",
		pair.ExpiresIn, len(pair.RefreshToken))
	return nil
}

func ex05(ctx context.Context, e *env) error {
	start := time.Now()
	_, err := e.auth.Login(ctx,
		service.LoginInput{Email: testEmail, Password: "wrong-password-123"}, nil, nil)
	elapsed := time.Since(start)
	if !errors.Is(err, apperr.ErrUnauthorized) {
		return fmt.Errorf("expected ErrUnauthorized, got %v", err)
	}
	if elapsed < 5*time.Millisecond {
		return fmt.Errorf("suspiciously fast for bad password: %v", elapsed)
	}
	fmt.Printf("wrong password: %v (ErrUnauthorized, >=5ms)\n", elapsed.Round(time.Millisecond))
	return nil
}

func ex06(ctx context.Context, e *env) error {
	start := time.Now()
	_, err := e.auth.Login(ctx,
		service.LoginInput{Email: "no-such-user@example.com", Password: "x"}, nil, nil)
	elapsed := time.Since(start)
	if !errors.Is(err, apperr.ErrUnauthorized) {
		return fmt.Errorf("expected ErrUnauthorized, got %v", err)
	}
	if elapsed < 5*time.Millisecond {
		return fmt.Errorf("suspiciously fast for unknown email: %v", elapsed)
	}
	fmt.Printf("unknown email: %v (ErrUnauthorized, >=5ms)\n", elapsed.Round(time.Millisecond))
	return nil
}

func ex07(ctx context.Context, e *env) error {
	if _, err := e.pool.Exec(ctx,
		`UPDATE users SET is_active = false WHERE id = $1`, testUserID); err != nil {
		return err
	}
	defer func() {
		_, _ = e.pool.Exec(context.Background(),
			`UPDATE users SET is_active = true WHERE id = $1`, testUserID)
	}()
	_, err := e.auth.Login(ctx,
		service.LoginInput{Email: testEmail, Password: testPass}, nil, nil)
	if !errors.Is(err, apperr.ErrForbidden) {
		return fmt.Errorf("expected ErrForbidden, got %v", err)
	}
	fmt.Println("inactive user: ErrForbidden =", true)
	return nil
}

func ex08(ctx context.Context, e *env) error {
	pair1, err := e.auth.Login(ctx,
		service.LoginInput{Email: testEmail, Password: testPass}, nil, nil)
	if err != nil {
		return err
	}
	pair2, err := e.auth.Refresh(ctx, pair1.RefreshToken, nil, nil)
	if err != nil {
		return err
	}
	if pair2.RefreshToken == pair1.RefreshToken {
		return fmt.Errorf("refresh token did not rotate")
	}
	if pair2.AccessToken == pair1.AccessToken {
		return fmt.Errorf("access token not reissued")
	}
	// Save the tokens for the following exercise.
	exTokens[testUserID] = pair1.RefreshToken
	fmt.Println("refresh rotated: both tokens changed")
	return nil
}

var exTokens = map[uuid.UUID]string{}

func ex09(ctx context.Context, e *env) error {
	oldRaw := exTokens[testUserID]
	oldHash := security.HashRefreshToken(oldRaw)
	var revokedAt *time.Time
	if err := e.pool.QueryRow(ctx,
		`SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1`, oldHash).Scan(&revokedAt); err != nil {
		return err
	}
	if revokedAt == nil {
		return fmt.Errorf("old token should be revoked")
	}
	fmt.Println("old token revoked_at set:", revokedAt.Format(time.RFC3339))
	return nil
}

func ex10(ctx context.Context, e *env) error {
	oldRaw := exTokens[testUserID]
	_, err := e.auth.Refresh(ctx, oldRaw, nil, nil)
	if !errors.Is(err, apperr.ErrUnauthorized) {
		return fmt.Errorf("expected ErrUnauthorized on reuse, got %v", err)
	}

	// All tokens in the family must now be revoked.
	var familyID uuid.UUID
	if err := e.pool.QueryRow(ctx,
		`SELECT family_id FROM refresh_tokens WHERE token_hash = $1`,
		security.HashRefreshToken(oldRaw)).Scan(&familyID); err != nil {
		return err
	}
	var active int
	if err := e.pool.QueryRow(ctx,
		`SELECT count(*) FROM refresh_tokens WHERE family_id = $1 AND revoked_at IS NULL`,
		familyID).Scan(&active); err != nil {
		return err
	}
	if active != 0 {
		return fmt.Errorf("family not fully revoked: %d still active", active)
	}
	fmt.Printf("reuse detected: family %s fully revoked (0 active)\n", familyID)
	return nil
}

func ex11(ctx context.Context, e *env) error {
	pair, err := e.auth.Login(ctx,
		service.LoginInput{Email: testEmail, Password: testPass}, nil, nil)
	if err != nil {
		return err
	}
	if err := e.auth.Logout(ctx, pair.RefreshToken); err != nil {
		return err
	}
	_, err = e.auth.Refresh(ctx, pair.RefreshToken, nil, nil)
	if !errors.Is(err, apperr.ErrUnauthorized) {
		return fmt.Errorf("expected ErrUnauthorized after logout, got %v", err)
	}
	// Idempotent second logout
	if err := e.auth.Logout(ctx, pair.RefreshToken); err != nil {
		return fmt.Errorf("second logout should be no-op: %w", err)
	}
	fmt.Println("logout: revoked, refresh fails, second logout is idempotent")
	return nil
}

func ex12(ctx context.Context, e *env) error {
	pair, err := e.auth.Login(ctx,
		service.LoginInput{Email: testEmail, Password: testPass}, nil, nil)
	if err != nil {
		return err
	}
	if err := e.auth.LogoutAll(ctx, testUserID); err != nil {
		return err
	}
	_, err = e.auth.Refresh(ctx, pair.RefreshToken, nil, nil)
	if !errors.Is(err, apperr.ErrUnauthorized) {
		return fmt.Errorf("expected ErrUnauthorized after logout-all, got %v", err)
	}
	fmt.Println("logout-all: revoked, refresh fails")
	return nil
}

func ex13(ctx context.Context, e *env) error {
	me, err := e.auth.Me(ctx, testUserID)
	if err != nil {
		return err
	}
	if me.User.ID != testUserID {
		return fmt.Errorf("wrong user")
	}
	roleNames := make([]string, 0, len(me.Roles))
	for _, r := range me.Roles {
		roleNames = append(roleNames, r.Name)
	}
	permCodes := make([]string, 0, len(me.Permissions))
	for _, p := range me.Permissions {
		permCodes = append(permCodes, p.Code)
	}
	if len(roleNames) != 1 || roleNames[0] != "user" {
		return fmt.Errorf("expected roles=[user], got %v", roleNames)
	}
	if len(permCodes) != 1 || permCodes[0] != "user.read" {
		return fmt.Errorf("expected perms=[user.read], got %v", permCodes)
	}
	fmt.Printf("me: id=%s roles=%v perms=%v\n", me.User.ID, roleNames, permCodes)
	return nil
}
