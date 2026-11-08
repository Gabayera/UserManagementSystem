package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"UserManagementSystem/apperr"
	"UserManagementSystem/domain"
	"UserManagementSystem/repository"
	"UserManagementSystem/service"

	"github.com/google/uuid"
)

func main() {
	repo := repository.NewMemoryUserRepo()
	svc := service.NewUserService(repo)
	ctx := context.Background()

	// --- Exercise 6: register + conflict ---

	alice, err := svc.Register(ctx, domain.RegisterRequest{
		Email:    "  Alice@Example.com ",
		Password: "password123",
		FullName: "Alice",
	})
	if err != nil {
		fmt.Println("register alice:", err)
		return
	}
	fmt.Printf("registered: %s (active=%v) at %s\n",
		alice.Email, alice.IsActive, alice.CreatedAt.Format(time.RFC3339))

	_, err = svc.Register(ctx, domain.RegisterRequest{
		Email:    "alice@example.com", // same email, different case/whitespace
		Password: "password123",
		FullName: "Alice Duplicate",
	})
	fmt.Printf("conflict check: err=%v | is-conflict=%v\n",
		err, errors.Is(err, apperr.ErrConflict))

	// --- Exercise 5: context deadline on SlowGet ---

	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, slowErr := svc.SlowGet(short, alice.ID)
	elapsed := time.Since(start)
	fmt.Printf("slowget: elapsed=%v err=%v | is-deadline=%v\n",
		elapsed.Round(time.Millisecond), slowErr,
		errors.Is(slowErr, context.DeadlineExceeded))

	// --- Sanity: Get happy path + not-found path ---

	got, err := svc.Get(ctx, alice.ID)
	if err != nil {
		fmt.Println("get:", err)
	} else {
		fmt.Printf("get: id=%s email=%s\n", got.ID, got.Email)
	}

	_, err = svc.Get(ctx, uuid.New())
	fmt.Printf("get missing: is-not-found=%v\n", errors.Is(err, apperr.ErrNotFound))
}