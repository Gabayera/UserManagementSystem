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
)

// RoleService owns role lifecycle and role↔permission grants.
// Business rules (deletion safety, audit) live here; SQL lives in the repo.
type RoleService struct {
	pool     *pgxpool.Pool
	roleRepo repository.RoleRepository
	audit    AuditService
}

func NewRoleService(
	pool *pgxpool.Pool,
	roleRepo repository.RoleRepository,
	audit AuditService,
) *RoleService {
	return &RoleService{pool: pool, roleRepo: roleRepo, audit: audit}
}

type CreateRoleInput struct {
	ActorUserID *uuid.UUID
	Name        string
	Description *string
}

type UpdateRoleInput struct {
	ActorUserID *uuid.UUID
	Name        *string
	Description *string
}

func (s *RoleService) Create(ctx context.Context, in CreateRoleInput) (*domain.Role, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 100 {
		return nil, apperr.Wrap(apperr.ErrValidation, "name must be 1-100 chars")
	}
	role := &domain.Role{ID: uuid.New(), Name: name, Description: in.Description}
	if err := s.roleRepo.Create(ctx, s.pool, role); err != nil {
		return nil, err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: in.ActorUserID,
		Action:      "role.created",
		EntityType:  "role",
		EntityID:    &role.ID,
		Metadata:    map[string]any{"name": role.Name},
	})
	return role, nil
}

func (s *RoleService) GetByID(ctx context.Context, id uuid.UUID) (*domain.Role, error) {
	return s.roleRepo.GetByID(ctx, s.pool, id)
}

func (s *RoleService) List(ctx context.Context, limit, offset int) ([]*domain.Role, int, error) {
	limit = clampLimit(limit)
	if offset < 0 {
		offset = 0
	}
	return s.roleRepo.List(ctx, s.pool, limit, offset)
}

func (s *RoleService) Update(ctx context.Context, id uuid.UUID, in UpdateRoleInput) (*domain.Role, error) {
	role, err := s.roleRepo.GetByID(ctx, s.pool, id)
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" || len(name) > 100 {
			return nil, apperr.Wrap(apperr.ErrValidation, "name must be 1-100 chars")
		}
		role.Name = name
	}
	if in.Description != nil {
		role.Description = in.Description
	}
	if err := s.roleRepo.Update(ctx, s.pool, role); err != nil {
		return nil, err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: in.ActorUserID,
		Action:      "role.updated",
		EntityType:  "role",
		EntityID:    &role.ID,
	})
	return role, nil
}

// SoftDelete refuses to delete a role that is still assigned to any user.
// This is the Part 9 keystone: it uses CountUsersWithRole to pre-check
// because user_roles.role_id has ON DELETE RESTRICT — but we soft-delete,
// so the FK never fires. Without this check, a role with 40 members could
// be soft-deleted and their permissions would silently vanish.
func (s *RoleService) SoftDelete(ctx context.Context, id uuid.UUID, actor *uuid.UUID) error {
	count, err := s.roleRepo.CountUsersWithRole(ctx, s.pool, id)
	if err != nil {
		return err
	}
	if count > 0 {
		return apperr.Wrap(apperr.ErrConflict, "role still assigned to %d user(s)", count)
	}
	if err := s.roleRepo.SoftDelete(ctx, s.pool, id); err != nil {
		return err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: actor,
		Action:      "role.deleted",
		EntityType:  "role",
		EntityID:    &id,
	})
	return nil
}

func (s *RoleService) AddPermission(ctx context.Context, roleID, permissionID uuid.UUID, actor *uuid.UUID) error {
	if err := s.roleRepo.AddPermission(ctx, s.pool, roleID, permissionID); err != nil {
		return err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: actor,
		Action:      "role.permission_added",
		EntityType:  "role",
		EntityID:    &roleID,
		Metadata:    map[string]any{"permission_id": permissionID.String()},
	})
	return nil
}

func (s *RoleService) RemovePermission(ctx context.Context, roleID, permissionID uuid.UUID, actor *uuid.UUID) error {
	if err := s.roleRepo.RemovePermission(ctx, s.pool, roleID, permissionID); err != nil {
		return err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: actor,
		Action:      "role.permission_removed",
		EntityType:  "role",
		EntityID:    &roleID,
		Metadata:    map[string]any{"permission_id": permissionID.String()},
	})
	return nil
}

func (s *RoleService) ListPermissions(ctx context.Context, roleID uuid.UUID) ([]*domain.Permission, error) {
	return s.roleRepo.PermissionsForRole(ctx, s.pool, roleID)
}

func (s *RoleService) auditBestEffort(ctx context.Context, entry AuditEntry) {
	if err := s.audit.Log(ctx, entry); err != nil {
		slog.Warn("audit_log_failed", "action", entry.Action, "err", err)
	}
}

// clampLimit is shared between services. 1 ≤ limit ≤ 100.
func clampLimit(limit int) int {
	if limit <= 0 {
		return 10
	}
	if limit > 100 {
		return 100
	}
	return limit
}
