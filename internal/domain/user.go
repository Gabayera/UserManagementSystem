package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	FullName     string
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
}

// NewUser builds a new, active user. CreatedAt/UpdatedAt are intentionally
// left zero: the database owns them (DEFAULT NOW()) and the repository's
// Create fills them back in via RETURNING, so the value the caller sees is
// exactly what was stored.
func NewUser(email, passwordHash, fullName string) *User {
	return &User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: passwordHash,
		FullName:     fullName,
		IsActive:     true,
	}
}
