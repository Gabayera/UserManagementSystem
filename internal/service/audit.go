package service

import (
	"context"

	"github.com/google/uuid"
)

type AuditEntry struct {
	ActorUserID *uuid.UUID
	Action      string
	EntityType  string
	EntityID    *uuid.UUID
	Metadata    map[string]any
	IPAddress   *string
	RequestID   string
}

type AuditService interface {
	Log(ctx context.Context, entry AuditEntry) error
}

type NoopAudit struct{}

func NewNoopAudit() *NoopAudit { return &NoopAudit{} }

func (NoopAudit) Log(ctx context.Context, _ AuditEntry) error { return nil }

var _ AuditService = (*NoopAudit)(nil)
