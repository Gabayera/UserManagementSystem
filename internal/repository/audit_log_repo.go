package repository

import (
	"context"

	"github.com/google/uuid"

	"UserManagementSystem/internal/domain"
)

type PGAuditLogRepo struct{}

func NewPGAuditLogRepo() *PGAuditLogRepo { return &PGAuditLogRepo{} }

var _ AuditLogRepository = (*PGAuditLogRepo)(nil)

const auditLogColumns = `id, actor_user_id, action, entity_type, entity_id, metadata, host(ip_address) AS ip_address, request_id, created_at`

func scanAuditLog(s interface{ Scan(dest ...any) error }) (*domain.AuditLog, error) {
	var l domain.AuditLog
	if err := s.Scan(
		&l.ID, &l.ActorUserID, &l.Action, &l.EntityType, &l.EntityID,
		&l.Metadata, &l.IPAddress, &l.RequestID, &l.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &l, nil
}

func (r *PGAuditLogRepo) Create(ctx context.Context, q Querier, l *domain.AuditLog) error {
	const sql = `INSERT INTO audit_logs (id, actor_user_id, action, entity_type, entity_id, metadata, ip_address, request_id)
	             VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8)`
	_, err := q.Exec(ctx, sql,
		l.ID, l.ActorUserID, l.Action, l.EntityType, l.EntityID,
		l.Metadata, l.IPAddress, l.RequestID,
	)
	return MapError(err)
}

func (r *PGAuditLogRepo) ListByActor(ctx context.Context, q Querier, actorID uuid.UUID, limit, offset int) ([]*domain.AuditLog, error) {
	const sql = `SELECT ` + auditLogColumns + `
	             FROM audit_logs
	             WHERE actor_user_id = $1
	             ORDER BY created_at DESC
	             LIMIT $2 OFFSET $3`
	rows, err := q.Query(ctx, sql, actorID, limit, offset)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	var out []*domain.AuditLog
	for rows.Next() {
		l, err := scanAuditLog(rows)
		if err != nil {
			return nil, MapError(err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}

func (r *PGAuditLogRepo) ListByEntity(ctx context.Context, q Querier, entityType string, entityID uuid.UUID, limit, offset int) ([]*domain.AuditLog, error) {
	const sql = `SELECT ` + auditLogColumns + `
	             FROM audit_logs
	             WHERE entity_type = $1 AND entity_id = $2
	             ORDER BY created_at DESC
	             LIMIT $3 OFFSET $4`
	rows, err := q.Query(ctx, sql, entityType, entityID, limit, offset)
	if err != nil {
		return nil, MapError(err)
	}
	defer rows.Close()

	var out []*domain.AuditLog
	for rows.Next() {
		l, err := scanAuditLog(rows)
		if err != nil {
			return nil, MapError(err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, MapError(err)
	}
	return out, nil
}
