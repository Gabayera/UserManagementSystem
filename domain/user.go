package domain

import (
	"time"
	"uuid"
)

type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	FullName     string
	IsActive     bool
	CreatedAt    *time.Time
	UpdatedAt    *time.Time
	DeletedAt    *time.Time
}

func NewUser(email string, passWordHash string) *User {
	t := time.Now()
	return &User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: passWordHash,
		IsActive:     true,
		CreatedAt:    &t,
		UpdatedAt:    &t,
		DeletedAt:    nil,
	}
}

