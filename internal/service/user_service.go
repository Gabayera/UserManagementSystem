package service

import (
	"context"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/domain"
	"UserManagementSystem/internal/repository"
	"UserManagementSystem/internal/security"
)

// UserService owns admin-driven user lifecycle. Distinct from AuthService:
// AuthService is "user does this to themselves"; UserService is "admin does
// this to someone else". Same tables, different audit semantics, different
// permission gate.
type UserService struct {
	pool     *pgxpool.Pool
	userRepo repository.UserRepository
	roleRepo repository.RoleRepository
	hasher   *security.PasswordHasher
	audit    AuditService
}

func NewUserService(
	pool *pgxpool.Pool,
	userRepo repository.UserRepository,
	roleRepo repository.RoleRepository,
	hasher *security.PasswordHasher,
	audit AuditService,
) *UserService {
	return &UserService{
		pool: pool, userRepo: userRepo, roleRepo: roleRepo,
		hasher: hasher, audit: audit,
	}
}

type CreateUserInput struct {
	ActorUserID *uuid.UUID
	Email       string
	Password    string
	FullName    string
}

type UpdateUserInput struct {
	ActorUserID *uuid.UUID
	FullName    *string
}

// Create is the admin path. It duplicates AuthService.Register's flow
// deliberately — same steps, different audit action, different actor.
func (s *UserService) Create(ctx context.Context, in CreateUserInput) (*domain.User, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	fullName := strings.TrimSpace(in.FullName)
	if email == "" || len(email) > 320 || !strings.Contains(email, "@") {
		return nil, apperr.Wrap(apperr.ErrValidation, "invalid email")
	}
	if fullName == "" || len(fullName) > 100 {
		return nil, apperr.Wrap(apperr.ErrValidation, "invalid full_name")
	}
	if len(in.Password) < 8 || len(in.Password) > 72 {
		return nil, apperr.Wrap(apperr.ErrValidation, "password must be 8-72 chars")
	}

	hash, err := s.hasher.Hash(ctx, in.Password)
	if err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, repository.MapError(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	u := domain.NewUser(email, hash, fullName)
	if err := s.userRepo.Create(ctx, tx, u); err != nil {
		return nil, err
	}
	defaultRole, err := s.roleRepo.GetByName(ctx, tx, "user")
	if err != nil {
		return nil, err
	}
	if err := s.userRepo.AssignRole(ctx, tx, u.ID, defaultRole.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, repository.MapError(err)
	}

	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: in.ActorUserID,
		Action:      "user.created_by_admin",
		EntityType:  "user",
		EntityID:    &u.ID,
		Metadata:    map[string]any{"email": u.Email},
	})
	return u, nil
}

func (s *UserService) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.userRepo.GetByID(ctx, s.pool, id)
}

func (s *UserService) List(ctx context.Context, limit, offset int) ([]*domain.User, int, error) {
	if limit <= 0 || limit > 100 {
		return nil, 0, apperr.Wrap(apperr.ErrValidation, "limit must be 1-100")
	}
	if offset < 0 {
		return nil, 0, apperr.Wrap(apperr.ErrValidation, "offset must be >= 0")
	}
	return s.userRepo.List(ctx, s.pool, limit, offset)
}

func (s *UserService) Update(ctx context.Context, id uuid.UUID, in UpdateUserInput) (*domain.User, error) {
	u, err := s.userRepo.GetByID(ctx, s.pool, id)
	if err != nil {
		return nil, err
	}
	if in.FullName != nil {
		fn := strings.TrimSpace(*in.FullName)
		if fn == "" || len(fn) > 100 {
			return nil, apperr.Wrap(apperr.ErrValidation, "full_name must be 1-100 chars")
		}
		u.FullName = fn
	}
	if err := s.userRepo.Update(ctx, s.pool, u); err != nil {
		return nil, err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: in.ActorUserID,
		Action:      "user.updated",
		EntityType:  "user",
		EntityID:    &u.ID,
	})
	return u, nil
}

func (s *UserService) SetActive(ctx context.Context, id uuid.UUID, active bool, actor *uuid.UUID) error {
	if err := s.userRepo.SetActive(ctx, s.pool, id, active); err != nil {
		return err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: actor,
		Action:      "user.status_changed",
		EntityType:  "user",
		EntityID:    &id,
		Metadata:    map[string]any{"is_active": active},
	})
	return nil
}

func (s *UserService) SoftDelete(ctx context.Context, id uuid.UUID, actor *uuid.UUID) error {
	if err := s.userRepo.SoftDelete(ctx, s.pool, id); err != nil {
		return err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: actor,
		Action:      "user.deleted",
		EntityType:  "user",
		EntityID:    &id,
	})
	return nil
}

func (s *UserService) AssignRole(ctx context.Context, userID, roleID uuid.UUID, actor *uuid.UUID) error {
	if err := s.userRepo.AssignRole(ctx, s.pool, userID, roleID); err != nil {
		return err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: actor,
		Action:      "user.role_assigned",
		EntityType:  "user",
		EntityID:    &userID,
		Metadata:    map[string]any{"role_id": roleID.String()},
	})
	return nil
}

func (s *UserService) RemoveRole(ctx context.Context, userID, roleID uuid.UUID, actor *uuid.UUID) error {
	if err := s.userRepo.RemoveRole(ctx, s.pool, userID, roleID); err != nil {
		return err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: actor,
		Action:      "user.role_removed",
		EntityType:  "user",
		EntityID:    &userID,
		Metadata:    map[string]any{"role_id": roleID.String()},
	})
	return nil
}

func (s *UserService) RolesForUser(ctx context.Context, userID uuid.UUID) ([]*domain.Role, error) {
	return s.userRepo.RolesForUser(ctx, s.pool, userID)
}

func (s *UserService) PermissionsForUser(ctx context.Context, userID uuid.UUID) ([]*domain.Permission, error) {
	return s.userRepo.PermissionsForUser(ctx, s.pool, userID)
}

func (s *UserService) auditBestEffort(ctx context.Context, entry AuditEntry) {
	if err := s.audit.Log(ctx, entry); err != nil {
		slog.Warn("audit_log_failed", "action", entry.Action, "err", err)
	}
}
