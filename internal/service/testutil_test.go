package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"UserManagementSystem/internal/repository"
	"UserManagementSystem/internal/security"
)

var (
	testPool  *pgxpool.Pool
	adminPool *pgxpool.Pool
)

const testSchema = "svc_test"

func TestMain(m *testing.M) {
	ctx := context.Background()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required for service integration tests")
	}

	var err error
	adminPool, err = pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Fatalf("admin pool: %v", err)
	}

	if _, err := adminPool.Exec(ctx, "DROP SCHEMA IF EXISTS "+testSchema+" CASCADE"); err != nil {
		log.Fatalf("drop schema: %v", err)
	}
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+testSchema); err != nil {
		log.Fatalf("create schema: %v", err)
	}

	// See repository/testutil_test.go for the reasoning: citext lives in
	// public; test schema has its own tables. search_path must include both.
	if _, err := adminPool.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS citext"); err != nil {
		log.Fatalf("create citext: %v", err)
	}

	testPool, err = newTestPool(ctx, databaseURL, testSchema)
	if err != nil {
		log.Fatalf("test pool: %v", err)
	}

	if err := applyMigrations(ctx, testPool); err != nil {
		log.Fatalf("migrations: %v", err)
	}

	code := m.Run()

	testPool.Close()
	_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+testSchema+" CASCADE")
	adminPool.Close()
	os.Exit(code)
}

func newTestPool(ctx context.Context, databaseURL, schema string) (*pgxpool.Pool, error) {
	pcfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	pcfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, fmt.Sprintf("SET search_path TO %s, public", schema))
		return err
	}
	return pgxpool.NewWithConfig(ctx, pcfg)
}

func applyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	migrationsDir := filepath.Join(dir, "..", "..", "migrations")

	for _, f := range []string{
		"000001_init.up.sql",
		"000002_seed_rbac.up.sql",
		"000003_split_user_read.up.sql",
		"000004_roles_name_unique_active.up.sql",
	} {
		b, err := os.ReadFile(filepath.Join(migrationsDir, f))
		if err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
		for _, stmt := range strings.Split(string(b), ";") {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := pool.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("%s: %w\nSQL: %s", f, err, stmt)
			}
		}
	}
	return nil
}

func resetUserTables(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `TRUNCATE users CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// buildAuthService constructs a real AuthService against the test schema.
// Uses the same PasswordHasher defaults as production (memory=19456, iter=2)
// so that if hashing time ever regresses past the timing-equalization window,
// the acceptance test in auth_test.go catches it.
func buildAuthService(t *testing.T) *AuthService {
	t.Helper()
	hasher := security.NewPasswordHasher(1)
	jwtIssuer := security.NewJWTIssuer(
		[]byte("test-secret-must-be-at-least-32-bytes-long"),
		"test",
		15*time.Minute,
	)
	svc, err := NewAuthService(
		testPool,
		repository.NewPGUserRepo(),
		repository.NewPGRefreshTokenRepo(),
		repository.NewPGRoleRepo(),
		hasher, jwtIssuer, NewNoopAudit(),
		15*time.Minute,
		7*24*time.Hour,
	)
	if err != nil {
		t.Fatalf("build auth service: %v", err)
	}
	return svc
}
