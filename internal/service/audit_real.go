package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/domain"
	"UserManagementSystem/internal/repository"
)

// RealAudit persists AuditEntry rows to the audit_logs table. It reads
// request-scoped metadata (request_id, ip_address) from the context.Context
// populated by middleware.RequestContext, so callers in Parts 7/9/11 don't
// need to thread them through manually.
//
// Failure semantics: caller sites use auditBestEffort — they log a warning
// and swallow the error. Business operations succeed even if audit fails.
// Deliberate: audit is important but not transactional with the business
// action. If audit writes failed the request, a broken audit sink would
// break user registration. Part 14 may add an AsyncAudit decorator (buffered
// channel + background writer) but the same fail-open behavior applies.
type RealAudit struct {
	pool *pgxpool.Pool
	repo repository.AuditLogRepository
}

func NewRealAudit(pool *pgxpool.Pool, repo repository.AuditLogRepository) *RealAudit {
	return &RealAudit{pool: pool, repo: repo}
}

var _ AuditService = (*RealAudit)(nil)

func (a *RealAudit) Log(ctx context.Context, entry AuditEntry) error {
	if entry.Action == "" {
		// Programmer error — better to fail loudly here than persist a
		// useless row that a reviewer has to debug from the DB.
		return apperr.Wrap(apperr.ErrValidation, "audit: action is required")
	}

	// Metadata must be non-nil: audit_logs.metadata is NOT NULL DEFAULT '{}'.
	// pgx marshals a nil map to JSON `null`, which violates the constraint
	// with SQLSTATE 23502. Every Logout call in Part 7 hits this path.
	md := entry.Metadata
	if md == nil {
		md = map[string]any{}
	}

	// Fill request_id + ip from RequestContext if not provided by caller.
	// Callers in Parts 7/9/11 don't set them (they don't know about HTTP),
	// so this is the normal path for every audit write in the codebase.
	rc, _ := RequestContextFromContext(ctx)
	reqID := entry.RequestID
	if reqID == "" {
		reqID = rc.RequestID
	}
	ip := entry.IPAddress
	if (ip == nil || *ip == "") && rc.IPAddress != "" {
		ipCopy := rc.IPAddress
		ip = &ipCopy
	}

	// CreatedAt is set for symmetry with domain.AuditLog, but the current
	// PGAuditLogRepo.Create does NOT insert created_at — the DB default
	// NOW() wins. That's fine for now: audit timestamps only need to be
	// "close enough to when it happened". If we later need exact
	// service-decision time (for dedup, correlation), we add created_at
	// to the INSERT in a Part 14 tweak to the repo.
	row := &domain.AuditLog{
		ID:          uuid.New(),
		ActorUserID: entry.ActorUserID,
		Action:      entry.Action,
		EntityType:  entityTypePtr(entry.EntityType),
		EntityID:    entry.EntityID,
		Metadata:    md,
		IPAddress:   ip,
		RequestID:   requestIDPtr(reqID),
		CreatedAt:   time.Now().UTC(),
	}

	if err := a.repo.Create(ctx, a.pool, row); err != nil {
		// %w on ErrUnavailable preserves errors.Is; %v on err keeps the
		// underlying detail in the log message without wrapping a pgx
		// error chain that no caller will ever need to unwrap.
		return fmt.Errorf("%w: audit create: %v", apperr.ErrUnavailable, err)
	}
	return nil
}

func entityTypePtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func requestIDPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
