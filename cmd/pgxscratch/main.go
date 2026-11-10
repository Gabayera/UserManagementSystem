package main 

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

type exercise func(context.Context, *pgxpool.Pool) error

func main() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fail("pool create", err)
	}
	defer pool.Close()

	if err := exSetup(ctx, pool); err != nil {
		fail("setup", err)
	}
	defer exTeardown(ctx, pool)

	exercises := []struct {
		name string
		fn   exercise
	}{
		{"exPing", exPing},
		{"exInsert", exInsert},
		{"exQueryRow", exQueryRow},
		{"exQueryRows", exQueryRows},
		{"exUniqueViolation", exUniqueViolation},
		{"exFKViolation", exFKViolation},
		{"exTxRollback", exTxRollback},
		{"exTxCommit", exTxCommit},
		{"exContextDeadline", exContextDeadline},
		{"exNullScan", exNullScan},
	}

	for _, e := range exercises {
		fmt.Printf("=== %s ===\n", e.name)
		if err := e.fn(ctx, pool); err != nil {
			fail(e.name, err)
		}
	}
}

func fail(operation string, err error) {
	log.Fatalf("%s: %v", operation, err)
}
