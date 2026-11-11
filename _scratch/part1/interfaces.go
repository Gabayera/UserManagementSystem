package repository

import (
	"context"

	"UserManagementSystem/domain"

	"github.com/google/uuid"
)


type UserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	Create(ctx context.Context, user *domain.User) error
	SlowGetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}
