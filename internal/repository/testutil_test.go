package repository

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	testPool  *pgxpool.Pool
	adminPool *pgxpool.Pool
)

const testSchema = "repo_test"

func TestMain(m *testing.M) {
	ctx := context.Background()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required for repository integration tests")
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

	// Ensure citext exists in `public` before the test schema uses it. If the
	// main DB already ran migration 1, this is a no-op. On a truly fresh DB
	// it installs into public (idempotent, safe).
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

// newTestPool creates a pool whose connections run with search_path set to
// "<schema>, public". public is included because citext (and any other
// extensions) live there; <schema> is first so CREATE TABLE and SELECT
// resolve to the isolated test schema rather than the production tables.
//
// Why AfterConnect instead of a URL parameter:
//   - pgx URL params like ?search_path=foo don't survive reliably (the value
//     is passed as `SET search_path = 'foo'` which quotes the whole thing).
//   - ?options=-c search_path=foo,public works but the URL-encoding of `=`
//     and `,` is fragile across pgx versions.
//   - AfterConnect runs on every new pooled connection, is explicit, and has
//     zero encoding ambiguity.
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

	files := []string{
		"000001_init.up.sql",
		"000002_seed_rbac.up.sql",
		"000003_split_user_read.up.sql",
		"000004_roles_name_unique_active.up.sql",
	}
	for _, f := range files {
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

func resetUserTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `TRUNCATE users CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
