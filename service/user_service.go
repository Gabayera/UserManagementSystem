package service

import (
	"context"
	"errors"
	"strings"

	"UserManagementSystem/apperr"
	"UserManagementSystem/domain"
	"UserManagementSystem/repository"

	"github.com/google/uuid"
)

type UserService struct {
	repo repository.UserRepository
}

func NewUserService(repo repository.UserRepository) *UserService {
	return &UserService{repo: repo}
}

func (s *UserService) Register(ctx context.Context, req domain.RegisterRequest) (*domain.User, error) {

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	fullName := strings.TrimSpace(req.FullName)

	if email == "" {
		return nil, apperr.Wrap(apperr.ErrValidation, "email is required")
	}
	if fullName == "" {
		return nil, apperr.Wrap(apperr.ErrValidation, "full_name is required")
	}
	if len(req.Password) < 8 {
		return nil, apperr.Wrap(apperr.ErrValidation, "password must be at least 8 characters")
	}

	// Duplicate check. A real error from the store is NOT "email free".
	_, err := s.repo.GetByEmail(ctx, email)
	switch {
	case err == nil:
		return nil, apperr.Wrap(apperr.ErrConflict, "email %s is already registered", email)
	case errors.Is(err, apperr.ErrNotFound):
		// not found → proceed
	default:
		return nil, apperr.Wrap(err, "check existing email")
	}

	u := domain.NewUser(email, req.Password, fullName)

	//Persist.
	if err := s.repo.Create(ctx, u); err != nil {
		return nil, apperr.Wrap(err, "create user")
	}
	return u, nil
}

func (s *UserService) Get(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	u, err := s.repo.GetByID(ctx, id) // C2 — pass uuid.UUID, not string
	if err != nil {
		if errors.Is(err, apperr.ErrNotFound) {
			return nil, apperr.Wrap(apperr.ErrNotFound, "user %s", id)
		}
		return nil, err
	}
	if u == nil {
		return nil, apperr.Wrap(apperr.ErrNotFound, "user %s", id)
	}
	return u, nil
}

func (s *UserService) SlowGet(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.repo.SlowGetByID(ctx, id) // C4 — use the slow method
}
