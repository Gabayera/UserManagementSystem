package domain

import (
	"time"

	"github.com/google/uuid"
)

// AuditLog records a business action. ActorUserID is nil for system actions
// and for actions whose actor has since been hard-deleted (ON DELETE SET NULL).
type AuditLog struct {
	ID          uuid.UUID
	ActorUserID *uuid.UUID
	Action      string
	EntityType  *string
	EntityID    *uuid.UUID
	Metadata    map[string]any
	IPAddress   *string
	RequestID   *string
	CreatedAt   time.Time
}
