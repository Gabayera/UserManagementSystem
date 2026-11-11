package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"UserManagementSystem/internal/domain"
)

// Querier is satisfied by both *pgxpool.Pool and pgx.Tx. Every repository
// method takes one so the caller decides whether work runs standalone or
// inside a caller-owned transaction.
//
// Repositories NEVER call Begin/Commit/Rollback themselves.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// UserRepository is the persistence contract for users.
//
// Contract:
//   - Read methods filter deleted_at IS NULL. Soft-deleted users are ErrNotFound.
//   - Create returns (wrapped) ErrConflict on duplicate active email.
//   - Update/SetActive/SoftDelete return ErrNotFound when RowsAffected == 0.
//   - AssignRole/RemoveRole are idempotent (no error if already assigned/removed).
type UserRepository interface {
	GetByID(ctx context.Context, q Querier, id uuid.UUID) (*domain.User, error)
	GetByEmail(ctx context.Context, q Querier, email string) (*domain.User, error)
	Create(ctx context.Context, q Querier, u *domain.User) error
	Update(ctx context.Context, q Querier, u *domain.User) error
	SetActive(ctx context.Context, q Querier, id uuid.UUID, active bool) error
	SoftDelete(ctx context.Context, q Querier, id uuid.UUID) error
	List(ctx context.Context, q Querier, limit, offset int) ([]*domain.User, int, error)

	AssignRole(ctx context.Context, q Querier, userID, roleID uuid.UUID) error
	RemoveRole(ctx context.Context, q Querier, userID, roleID uuid.UUID) error
	RolesForUser(ctx context.Context, q Querier, userID uuid.UUID) ([]*domain.Role, error)
	PermissionsForUser(ctx context.Context, q Querier, userID uuid.UUID) ([]*domain.Permission, error)
}

// RoleRepository is the persistence contract for roles.
type RoleRepository interface {
	GetByID(ctx context.Context, q Querier, id uuid.UUID) (*domain.Role, error)
	GetByName(ctx context.Context, q Querier, name string) (*domain.Role, error)
	Create(ctx context.Context, q Querier, r *domain.Role) error
	Update(ctx context.Context, q Querier, r *domain.Role) error
	SoftDelete(ctx context.Context, q Querier, id uuid.UUID) error
	List(ctx context.Context, q Querier, limit, offset int) ([]*domain.Role, int, error)

	AddPermission(ctx context.Context, q Querier, roleID, permissionID uuid.UUID) error
	RemovePermission(ctx context.Context, q Querier, roleID, permissionID uuid.UUID) error
	PermissionsForRole(ctx context.Context, q Querier, roleID uuid.UUID) ([]*domain.Permission, error)
}

// PermissionRepository is the persistence contract for permissions.
//
// Permissions are configuration: hard-delete, no soft delete.
type PermissionRepository interface {
	GetByID(ctx context.Context, q Querier, id uuid.UUID) (*domain.Permission, error)
	GetByCode(ctx context.Context, q Querier, code string) (*domain.Permission, error)
	Create(ctx context.Context, q Querier, p *domain.Permission) error
	Update(ctx context.Context, q Querier, p *domain.Permission) error
	Delete(ctx context.Context, q Querier, id uuid.UUID) error
	List(ctx context.Context, q Querier, limit, offset int) ([]*domain.Permission, int, error)
}

// RefreshTokenRepository is the persistence contract for session tokens.
//
// Contract:
//   - Revoke* methods are idempotent (no error if already revoked).
//   - Rotate MUST be called with a pgx.Tx. It fails with ErrNotFound if the
//     old row is already revoked (reuse-detection signal for the caller).
type RefreshTokenRepository interface {
	Create(ctx context.Context, q Querier, t *domain.RefreshToken) error
	GetByHash(ctx context.Context, q Querier, hash string) (*domain.RefreshToken, error)
	RevokeByID(ctx context.Context, q Querier, id uuid.UUID) error
	RevokeByFamily(ctx context.Context, q Querier, familyID uuid.UUID) error
	RevokeAllForUser(ctx context.Context, q Querier, userID uuid.UUID) error
	Rotate(ctx context.Context, q Querier, oldID uuid.UUID, newToken *domain.RefreshToken) error
}

// AuditLogRepository is the persistence contract for audit logs.
type AuditLogRepository interface {
	Create(ctx context.Context, q Querier, log *domain.AuditLog) error
	ListByActor(ctx context.Context, q Querier, actorID uuid.UUID, limit, offset int) ([]*domain.AuditLog, error)
	ListByEntity(ctx context.Context, q Querier, entityType string, entityID uuid.UUID, limit, offset int) ([]*domain.AuditLog, error)
}
