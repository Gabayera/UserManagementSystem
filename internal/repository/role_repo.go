package repository

import (
	"context"

	"github.com/google/uuid"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/domain"
)

type PGRoleRepo struct{}

func NewPGRoleRepo() *PGRoleRepo { return &PGRoleRepo{} }

var _ RoleRepository = (*PGRoleRepo)(nil)

const roleColumns = `id, name, description, created_at, updated_at, deleted_at`

func scanRole(s interface{ Scan(dest ...any) error }) (*domain.Role, error) {
	var r domain.Role
	if err := s.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt, &r.UpdatedAt, &r.DeletedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *PGRoleRepo) GetByID(ctx context.Context, q Querier, id uuid.UUID) (*domain.Role, error) {
	const sql = `SELECT ` + roleColumns + ` FROM roles WHERE id = $1 AND deleted_at IS NULL`
	ro, err := scanRole(q.QueryRow(ctx, sql, id))
	if err != nil {
		return nil, MapError(err)
	}
	return ro, nil
}

func (r *PGRoleRepo) GetByName(ctx context.Context, q Querier, name string) (*domain.Role, error) {
	const sql = `SELECT ` + roleColumns + ` FROM roles WHERE name = $1 AND deleted_at IS NULL`
	ro, err := scanRole(q.QueryRow(ctx, sql, name))
	if err != nil {
		return nil, MapError(err)
	}
	return ro, nil
}

func (r *PGRoleRepo) Create(ctx context.Context, q Querier, ro *domain.Role) error {
	const sql = `INSERT INTO roles (id, name, description) VALUES ($1, $2, $3)`
	_, err := q.Exec(ctx, sql, ro.ID, ro.Name, ro.Description)
	return MapError(err)
}

func (r *PGRoleRepo) Update(ctx context.Context, q Querier, ro *domain.Role) error {
	const sql = `UPDATE roles SET name = $2, description = $3, updated_at = NOW()
	             WHERE id = $1 AND deleted_at IS NULL`
	tag, err := q.Exec(ctx, sql, ro.ID, ro.Name, ro.Description)
	if err != nil {
		return MapError(err)
	}
	if tag.RowsAffected() == 0 {
		return apperr.ErrNotFound
	}
	return nil
}

// SoftDelete only sets deleted_at. It does NOT fail if the role is still
// assigned to users — the SERVICE pre-checks role usage (Part 9).
func (r *PGRoleRepo) SoftDelete(ctx context.Context, q Querier, id uuid.UUID) error {
	const sql = `UPDATE roles SET deleted_at = NOW(), updated_at = NOW()
	             WHERE id = $1 AND deleted_at IS NULL`
	tag, err := q.Exec(ctx, sql, id)
	if err != nil {
		return MapError(err)
	}
	if tag.RowsAffected() == 0 {
		return apperr.ErrNotFound
	}
	return nil
}

func (r *PGRoleRepo) List(ctx context.Context, q Querier, limit, offset int) ([]*domain.Role, int, error) {
	const countSQL = `SELECT count(*) FROM roles WHERE deleted_at IS NULL`
	var total int
	if err := q.QueryRow(ctx, countSQL).Scan(&total); err != nil {
		return nil, 0, MapError(err)
	}
	const listSQL = `SELECT ` + roleColumns + ` FROM roles
	                 WHERE deleted_at IS NULL
	                 ORDER BY name LIMIT $1 OFFSET $2`
	rows, err := q.Query(ctx, listSQL, limit, offset)
	if err != nil {
		return nil, 0, MapError(err)
	}
	defer rows.Close()

	out := make([]*domain.Role, 0, limit)
	for rows.Next() {
		ro, err := scanRole(rows)
		if err != nil {
			return nil, 0, MapError(err)
		}
		out = append(out, ro)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, MapError(err)
	}
	return out, total, nil
}

func (r *PGRoleRepo) AddPermission(ctx context.Context, q Querier, roleID, permissionID uuid.UUID) error {
	const sql = `INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)
	             ON CONFLICT (role_id, permission_id) DO NOTHING`
	_, err := q.Exec(ctx, sql, roleID, permissionID)
	return MapError(err)
}

func (r *PGRoleRepo) RemovePermission(ctx context.Context, q Querier, roleID, permissionID uuid.UUID) error {
	const sql = `DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`
	_, err := q.Exec(ctx, sql, roleID, permissionID)
	return MapError(err)
}

func (r *PGRoleRepo) PermissionsForRole(ctx context.Context, q Querier, roleID uuid.UUID) ([]*domain.Permission, error) {
	const sql = `
		SELECT p.id, p.code, p.description, p.created_at, p.updated_at
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		WHERE rp.role_id = $1
		ORDER BY p.code`
	rows, err := q.Query(ctx, sql, roleID)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	var out []*domain.Permission
	for rows.Next() {
		var p domain.Permission
		if err := rows.Scan(&p.ID, &p.Code, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, MapError(err)
		}
		out = append(out, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}
