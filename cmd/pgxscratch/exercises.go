package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func exSetup(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS demo_books CASCADE`); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS demo_authors CASCADE`); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE demo_authors (
			id   bigserial PRIMARY KEY,
			name text NOT NULL
		)`); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE demo_books (
			id        bigserial PRIMARY KEY,
			isbn      text   NOT NULL UNIQUE,
			author_id bigint NOT NULL REFERENCES demo_authors(id),
			note      text
		)`); err != nil {
		return err
	}
	fmt.Println("setup: demo_authors + demo_books created")
	return nil
}

func exTeardown(ctx context.Context, pool *pgxpool.Pool) {
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS demo_books CASCADE`); err != nil {
		fmt.Println("teardown demo_books:", err)
	}
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS demo_authors CASCADE`); err != nil {
		fmt.Println("teardown demo_authors:", err)
	}
}

func exPing(ctx context.Context, pool *pgxpool.Pool) error {
	if err := pool.Ping(ctx); err != nil {
		return err
	}
	fmt.Println("pool pinged")
	return nil
}

func exInsert(ctx context.Context, pool *pgxpool.Pool) error {
	tag, err := pool.Exec(ctx,
		`INSERT INTO demo_authors (name) VALUES ($1)`, "Matin")
	if err != nil {
		return err
	}
	fmt.Printf("tag=%q rowsAffected=%d\n", tag.String(), tag.RowsAffected())
	return nil
}

func exQueryRow(ctx context.Context, pool *pgxpool.Pool) error {
	var name string
	err := pool.QueryRow(ctx,
		`SELECT name FROM demo_authors WHERE id = $1`, 1).Scan(&name)
	if err != nil {
		return err
	}
	fmt.Println("found:", name)

	err = pool.QueryRow(ctx,
		`SELECT name FROM demo_authors WHERE id = $1`, 999999).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		fmt.Println("not found: errors.Is(err, pgx.ErrNoRows) = true")
		return nil
	}
	return fmt.Errorf("expected ErrNoRows, got: %v", err)
}

func exQueryRows(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `SELECT id, name FROM demo_authors ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var n int
	for rows.Next() {
		var (
			id   int64
			name string
		)
		if err := rows.Scan(&id, &name); err != nil {
			return err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	fmt.Println("rows:", n)
	return nil
}

func exUniqueViolation(ctx context.Context, pool *pgxpool.Pool) error {
	q := `INSERT INTO demo_books (isbn, author_id) VALUES ($1, $2)`

	if _, err := pool.Exec(ctx, q, "111", 1); err != nil {
		return err
	}
	_, err := pool.Exec(ctx, q, "111", 1)

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		fmt.Printf("code=%s constraint=%s msg=%s\n",
			pgErr.Code, pgErr.ConstraintName, pgErr.Message)
		return nil
	}
	return fmt.Errorf("expected PgError, got: %v", err)
}

func exFKViolation(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO demo_books (isbn, author_id) VALUES ($1, $2)`,
		"222", 999999)

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		fmt.Printf("code=%s constraint=%s\n", pgErr.Code, pgErr.ConstraintName)
		return nil
	}
	return fmt.Errorf("expected PgError, got: %v", err)
}

func exTxRollback(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO demo_books (isbn, author_id) VALUES ($1, $2)`,
		"333", 1); err != nil {
		return err
	}
	if err := tx.Rollback(ctx); err != nil {
		return err
	}

	var id int64
	err = pool.QueryRow(ctx,
		`SELECT id FROM demo_books WHERE isbn = $1`, "333").Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		fmt.Println("after rollback: row absent (ErrNoRows)")
		return nil
	}
	return fmt.Errorf("row should be absent, got id=%d err=%v", id, err)
}

func exTxCommit(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO demo_books (isbn, author_id) VALUES ($1, $2)`,
		"444", 1); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	var id int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM demo_books WHERE isbn = $1`, "444").Scan(&id); err != nil {
		return fmt.Errorf("row should be present: %w", err)
	}
	fmt.Println("after commit: row present, id =", id)
	return nil
}

func exContextDeadline(ctx context.Context, pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	_, err := pool.Exec(ctx, `SELECT pg_sleep(5)`)
	if err == nil {
		return errors.New("expected timeout, got nil")
	}

	fmt.Println("errors.Is DeadlineExceeded:", errors.Is(err, context.DeadlineExceeded))

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		fmt.Println("PgError code:", pgErr.Code)
	}
	fmt.Println("raw error:", err)
	return nil
}

func exNullScan(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx,
		`INSERT INTO demo_books (isbn, author_id, note) VALUES ($1, $2, NULL)`,
		"555", 1); err != nil {
		return err
	}

	var note *string
	if err := pool.QueryRow(ctx,
		`SELECT note FROM demo_books WHERE isbn = $1`, "555").Scan(&note); err != nil {
		return err
	}
	fmt.Println("note is nil:", note == nil)

	var plain string
	err := pool.QueryRow(ctx,
		`SELECT note FROM demo_books WHERE isbn = $1`, "555").Scan(&plain)
	fmt.Println("scan NULL into string ->", err)
	return nil
}
