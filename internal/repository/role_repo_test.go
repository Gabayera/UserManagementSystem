package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"UserManagementSystem/internal/domain"
)

func TestPGRoleRepo_Create_ReusesNameAfterSoftDelete(t *testing.T) {
	ctx := context.Background()
	repo := NewPGRoleRepo()
	name := "reusable-" + uuid.NewString()

	first := &domain.Role{ID: uuid.New(), Name: name}
	requireNoErr(t, repo.Create(ctx, testPool, first))
	requireNoErr(t, repo.SoftDelete(ctx, testPool, first.ID))

	second := &domain.Role{ID: uuid.New(), Name: name}
	if err := repo.Create(ctx, testPool, second); err != nil {
		t.Fatalf("create role with reused name: %v", err)
	}
}
