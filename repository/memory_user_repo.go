package repository

import (
	"context"
	"fmt"
	"sync"
	"time"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/domain"

	"github.com/google/uuid"
)

type MemoryUserRepo struct {
	mu    sync.RWMutex
	users map[uuid.UUID]*domain.User
}

func NewMemoryUserRepo() *MemoryUserRepo {
	return &MemoryUserRepo{users: make(map[uuid.UUID]*domain.User)}
}

func (r *MemoryUserRepo) Create(ctx context.Context, u *domain.User) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if u == nil {
		return &apperr.ValidationError{Field: "user", Reason: "must not be nil"}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, existing := range r.users {
		if existing != nil &&
			existing.Email == u.Email &&
			existing.DeletedAt == nil {
			return fmt.Errorf("%w: email %s", apperr.ErrConflict, u.Email)
		}
	}

	r.users[u.ID] = u
	return nil
}

func (r *MemoryUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	user, ok := r.users[id]
	r.mu.RUnlock()

	if !ok || user == nil || user.DeletedAt != nil { 
		return nil, apperr.Wrap(apperr.ErrNotFound, "user id %s", id)
	}
	return user, nil
}

func (r *MemoryUserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, user := range r.users {
		if user != nil && user.Email == email && user.DeletedAt == nil {
			return user, nil
		}
	}
	return nil, apperr.Wrap(apperr.ErrNotFound, "user email %s", email)
}

func (r *MemoryUserRepo) SlowGetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	select {
	case <-time.After(200 * time.Millisecond):
		return r.GetByID(ctx, id)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}