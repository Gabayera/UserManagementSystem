package domain

import (
	"time"

	"github.com/google/uuid"
)

// Permission is a fine-grained capability code (e.g. "user.read"). Permissions
// are configuration, not entities — no soft delete
type Permission struct {
	ID          uuid.UUID
	Code        string
	Description *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
