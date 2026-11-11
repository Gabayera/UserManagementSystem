package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/domain"
)

type PGUserRepo struct{}

func NewPGUserRepo() *PGUserRepo { return &PGUserRepo{} }

var _ UserRepository = (*PGUserRepo)(nil)

const userColumns = `id, email::text, password_hash, full_name, is_active, created_at, updated_at, deleted_at`

func scanUser(s interface {
	Scan(dest ...any) error
}) (*domain.User, error) {
	var u domain.User
	if err := s.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.FullName, &u.IsActive,
		&u.CreatedAt, &u.UpdatedAt, &u.DeletedAt,
	); err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *PGUserRepo) GetByID(ctx context.Context, q Querier, id uuid.UUID) (*domain.User, error) {
	const sql = `SELECT ` + userColumns + ` FROM users WHERE id = $1 AND deleted_at IS NULL`
	u, err := scanUser(q.QueryRow(ctx, sql, id))
	if err != nil {
		return nil, MapError(err)
	}
	return u, nil
}

func (r *PGUserRepo) GetByEmail(ctx context.Context, q Querier, email string) (*domain.User, error) {
	const sql = `SELECT ` + userColumns + ` FROM users WHERE email = $1 AND deleted_at IS NULL`
	u, err := scanUser(q.QueryRow(ctx, sql, email))
	if err != nil {
		return nil, MapError(err)
	}
	return u, nil
}

// Create inserts a new user. created_at/updated_at are DB-generated (NOW()).
// Returns ErrConflict on duplicate live email.
func (r *PGUserRepo) Create(ctx context.Context, q Querier, u *domain.User) error {
	const sql = `INSERT INTO users (id, email, password_hash, full_name, is_active)
	             VALUES ($1, $2, $3, $4, $5)`
	_, err := q.Exec(ctx, sql, u.ID, u.Email, u.PasswordHash, u.FullName, u.IsActive)
	return MapError(err)
}

func (r *PGUserRepo) Update(ctx context.Context, q Querier, u *domain.User) error {
	const sql = `UPDATE users SET full_name = $2, updated_at = NOW()
	             WHERE id = $1 AND deleted_at IS NULL`
	tag, err := q.Exec(ctx, sql, u.ID, u.FullName)
	if err != nil {
		return MapError(err)
	}
	if tag.RowsAffected() == 0 {
		return apperr.ErrNotFound
	}
	return nil
}

func (r *PGUserRepo) SetActive(ctx context.Context, q Querier, id uuid.UUID, active bool) error {
	const sql = `UPDATE users SET is_active = $2, updated_at = NOW()
	             WHERE id = $1 AND deleted_at IS NULL`
	tag, err := q.Exec(ctx, sql, id, active)
	if err != nil {
		return MapError(err)
	}
	if tag.RowsAffected() == 0 {
		return apperr.ErrNotFound
	}
	return nil
}

func (r *PGUserRepo) SoftDelete(ctx context.Context, q Querier, id uuid.UUID) error {
	const sql = `UPDATE users SET deleted_at = NOW(), updated_at = NOW()
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

func (r *PGUserRepo) List(ctx context.Context, q Querier, limit, offset int) ([]*domain.User, int, error) {
	const countSQL = `SELECT count(*) FROM users WHERE deleted_at IS NULL`
	var total int
	if err := q.QueryRow(ctx, countSQL).Scan(&total); err != nil {
		return nil, 0, MapError(err)
	}

	const listSQL = `SELECT ` + userColumns + ` FROM users
	                 WHERE deleted_at IS NULL
	                 ORDER BY created_at DESC, id
	                 LIMIT $1 OFFSET $2`
	rows, err := q.Query(ctx, listSQL, limit, offset)
	if err != nil {
		return nil, 0, MapError(err)
	}
	defer rows.Close()

	out := make([]*domain.User, 0, limit)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, MapError(err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, MapError(err)
	}
	return out, total, nil
}

// AssignRole is idempotent: assigning a role that's already assigned is not an error.
func (r *PGUserRepo) AssignRole(ctx context.Context, q Querier, userID, roleID uuid.UUID) error {
	const sql = `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)
	             ON CONFLICT (user_id, role_id) DO NOTHING`
	_, err := q.Exec(ctx, sql, userID, roleID)
	return MapError(err)
}

// RemoveRole is idempotent: removing a role that isn't assigned is not an error.
func (r *PGUserRepo) RemoveRole(ctx context.Context, q Querier, userID, roleID uuid.UUID) error {
	const sql = `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`
	_, err := q.Exec(ctx, sql, userID, roleID)
	return MapError(err)
}

func (r *PGUserRepo) RolesForUser(ctx context.Context, q Querier, userID uuid.UUID) ([]*domain.Role, error) {
	const sql = `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at, r.deleted_at
		FROM roles r
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1 AND r.deleted_at IS NULL
		ORDER BY r.name`
	rows, err := q.Query(ctx, sql, userID)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	var out []*domain.Role
	for rows.Next() {
		var ro domain.Role
		if err := rows.Scan(&ro.ID, &ro.Name, &ro.Description, &ro.CreatedAt, &ro.UpdatedAt, &ro.DeletedAt); err != nil {
			return nil, MapError(err)
		}
		out = append(out, &ro)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

// PermissionsForUser returns the DISTINCT union of permissions across all of
// the user's live roles. Two roles sharing user.read yields one row.
func (r *PGUserRepo) PermissionsForUser(ctx context.Context, q Querier, userID uuid.UUID) ([]*domain.Permission, error) {
	const sql = `
		SELECT DISTINCT p.id, p.code, p.description, p.created_at, p.updated_at
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		JOIN roles r ON r.id = rp.role_id AND r.deleted_at IS NULL
		JOIN user_roles ur ON ur.role_id = r.id
		WHERE ur.user_id = $1
		ORDER BY p.code`
	rows, err := q.Query(ctx, sql, userID)
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

// ensure fmt is used (referenced by future expansions in this file, kept so
// adding a WARN log inline stays a one-line change).
var _ = fmt.Sprintf
