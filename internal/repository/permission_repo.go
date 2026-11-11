package repository

import (
	"context"

	"github.com/google/uuid"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/domain"
)

type PGPermissionRepo struct{}

func NewPGPermissionRepo() *PGPermissionRepo { return &PGPermissionRepo{} }

var _ PermissionRepository = (*PGPermissionRepo)(nil)

const permissionColumns = `id, code, description, created_at, updated_at`

func scanPermission(s interface{ Scan(dest ...any) error }) (*domain.Permission, error) {
	var p domain.Permission
	if err := s.Scan(&p.ID, &p.Code, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *PGPermissionRepo) GetByID(ctx context.Context, q Querier, id uuid.UUID) (*domain.Permission, error) {
	const sql = `SELECT ` + permissionColumns + ` FROM permissions WHERE id = $1`
	p, err := scanPermission(q.QueryRow(ctx, sql, id))
	if err != nil {
		return nil, MapError(err)
	}
	return p, nil
}

func (r *PGPermissionRepo) GetByCode(ctx context.Context, q Querier, code string) (*domain.Permission, error) {
	const sql = `SELECT ` + permissionColumns + ` FROM permissions WHERE code = $1`
	p, err := scanPermission(q.QueryRow(ctx, sql, code))
	if err != nil {
		return nil, MapError(err)
	}
	return p, nil
}

func (r *PGPermissionRepo) Create(ctx context.Context, q Querier, p *domain.Permission) error {
	const sql = `INSERT INTO permissions (id, code, description) VALUES ($1, $2, $3)`
	_, err := q.Exec(ctx, sql, p.ID, p.Code, p.Description)
	return MapError(err)
}

func (r *PGPermissionRepo) Update(ctx context.Context, q Querier, p *domain.Permission) error {
	const sql = `UPDATE permissions SET code = $2, description = $3, updated_at = NOW() WHERE id = $1`
	tag, err := q.Exec(ctx, sql, p.ID, p.Code, p.Description)
	if err != nil {
		return MapError(err)
	}
	if tag.RowsAffected() == 0 {
		return apperr.ErrNotFound
	}
	return nil
}

func (r *PGPermissionRepo) Delete(ctx context.Context, q Querier, id uuid.UUID) error {
	const sql = `DELETE FROM permissions WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id)
	if err != nil {
		return MapError(err)
	}
	if tag.RowsAffected() == 0 {
		return apperr.ErrNotFound
	}
	return nil
}

func (r *PGPermissionRepo) List(ctx context.Context, q Querier, limit, offset int) ([]*domain.Permission, int, error) {
	const countSQL = `SELECT count(*) FROM permissions`
	var total int
	if err := q.QueryRow(ctx, countSQL).Scan(&total); err != nil {
		return nil, 0, MapError(err)
	}
	const listSQL = `SELECT ` + permissionColumns + ` FROM permissions
	                 ORDER BY code LIMIT $1 OFFSET $2`
	rows, err := q.Query(ctx, listSQL, limit, offset)
	if err != nil {
		return nil, 0, MapError(err)
	}
	defer rows.Close()

	out := make([]*domain.Permission, 0, limit)
	for rows.Next() {
		p, err := scanPermission(rows)
		if err != nil {
			return nil, 0, MapError(err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, MapError(err)
	}
	return out, total, nil
}
