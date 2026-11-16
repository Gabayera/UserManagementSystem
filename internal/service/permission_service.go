package service

import (
	"context"
	"log/slog"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/domain"
	"UserManagementSystem/internal/repository"
)

// PermissionService owns permission definitions. Codes are the stable,
// wire-visible identifiers ("user.read"); they are immutable after creation.
type PermissionService struct {
	pool     *pgxpool.Pool
	permRepo repository.PermissionRepository
	audit    AuditService
}

var permissionCodeRe = regexp.MustCompile(`^[a-z][a-z0-9._]*$`)

func NewPermissionService(
	pool *pgxpool.Pool,
	permRepo repository.PermissionRepository,
	audit AuditService,
) *PermissionService {
	return &PermissionService{pool: pool, permRepo: permRepo, audit: audit}
}

type CreatePermissionInput struct {
	ActorUserID *uuid.UUID
	Code        string
	Description *string
}

type UpdatePermissionInput struct {
	ActorUserID *uuid.UUID
	Description *string
}

func (s *PermissionService) Create(ctx context.Context, in CreatePermissionInput) (*domain.Permission, error) {
	code := strings.TrimSpace(in.Code)
	if len(code) == 0 || len(code) > 100 || !permissionCodeRe.MatchString(code) {
		return nil, apperr.Wrap(apperr.ErrValidation,
			"code must match %s (lowercase, 1-100 chars)", permissionCodeRe.String())
	}
	perm := &domain.Permission{ID: uuid.New(), Code: code, Description: in.Description}
	if err := s.permRepo.Create(ctx, s.pool, perm); err != nil {
		return nil, err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: in.ActorUserID,
		Action:      "permission.created",
		EntityType:  "permission",
		EntityID:    &perm.ID,
		Metadata:    map[string]any{"code": perm.Code},
	})
	return perm, nil
}

func (s *PermissionService) GetByID(ctx context.Context, id uuid.UUID) (*domain.Permission, error) {
	return s.permRepo.GetByID(ctx, s.pool, id)
}

func (s *PermissionService) GetByCode(ctx context.Context, code string) (*domain.Permission, error) {
	return s.permRepo.GetByCode(ctx, s.pool, code)
}

func (s *PermissionService) List(ctx context.Context, limit, offset int) ([]*domain.Permission, int, error) {
	limit = clampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	return s.permRepo.List(ctx, s.pool, limit, offset)
}

func (s *PermissionService) Update(ctx context.Context, id uuid.UUID, in UpdatePermissionInput) (*domain.Permission, error) {
	perm, err := s.permRepo.GetByID(ctx, s.pool, id)
	if err != nil {
		return nil, err
	}
	if in.Description != nil {
		perm.Description = in.Description
	}
	if err := s.permRepo.Update(ctx, s.pool, perm); err != nil {
		return nil, err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: in.ActorUserID,
		Action:      "permission.updated",
		EntityType:  "permission",
		EntityID:    &perm.ID,
	})
	return perm, nil
}

// Delete refuses to delete a permission still granted to any role. Same
// reasoning as RoleService.SoftDelete: role_permissions FKs block the delete
// but we want a friendly ErrConflict, not a raw 23503.
func (s *PermissionService) Delete(ctx context.Context, id uuid.UUID, actor *uuid.UUID) error {
	count, err := s.permRepo.CountRoleUsages(ctx, s.pool, id)
	if err != nil {
		return err
	}
	if count > 0 {
		return apperr.Wrap(apperr.ErrConflict, "permission still granted to %d role(s)", count)
	}
	if err := s.permRepo.Delete(ctx, s.pool, id); err != nil {
		return err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: actor,
		Action:      "permission.deleted",
		EntityType:  "permission",
		EntityID:    &id,
	})
	return nil
}

func (s *PermissionService) auditBestEffort(ctx context.Context, entry AuditEntry) {
	if err := s.audit.Log(ctx, entry); err != nil {
		slog.Warn("audit_log_failed", "action", entry.Action, "err", err)
	}
}
