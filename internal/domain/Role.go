package domain

import (
	"time"

	"github.com/google/uuid"
)

// Role is a persisted role. Soft-deleted (DeletedAt != nil) roles are treated
// as not found by the repository layer and by authorization resolution.
type Role struct {
	ID          uuid.UUID
	Name        string
	Description *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}
