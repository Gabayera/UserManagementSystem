package domain

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken is a persisted session token. Only the SHA-256 hash of the raw
// token is stored (TokenHash). FamilyID groups all tokens descended from one
// login, so reuse detection can revoke the whole chain.
//
// IPAddress is nullable and stored as text; the repository casts to/from INET
type RefreshToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	FamilyID   uuid.UUID
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy *uuid.UUID
	UserAgent  *string
	IPAddress  *string // note: nullable, stored as text in Go
	CreatedAt  time.Time
}
