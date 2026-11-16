package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"UserManagementSystem/internal/repository"
)

// PermissionsResolver is the seam Part 10's RequirePermission middleware
// depends on. It returns the set of permission codes for a user so membership
// checks are O(1). Defined at the consumer (DIP) — Part 10 doesn't need the
// DB-backed implementation; it needs this capability.
//
// The contract is:
//   - Never returns nil; returns an empty non-nil map for users with no perms.
//   - Filters out permissions granted only via soft-deleted roles.
//   - Does not deduplicate across roles in memory — the SQL DISTINCT already
//     handles that (see repository.PGUserRepo.PermissionsForUser).
type PermissionsResolver interface {
	PermissionsForUser(ctx context.Context, userID uuid.UUID) (map[string]struct{}, error)
}

// DBPermissionsResolver is the direct-from-DB implementation. Part 12 may
// wrap this in a caching decorator without touching Part 10.
type DBPermissionsResolver struct {
	pool     *pgxpool.Pool
	userRepo repository.UserRepository
}

func NewDBPermissionsResolver(
	pool *pgxpool.Pool,
	userRepo repository.UserRepository,
) *DBPermissionsResolver {
	return &DBPermissionsResolver{pool: pool, userRepo: userRepo}
}

var _ PermissionsResolver = (*DBPermissionsResolver)(nil)

func (r *DBPermissionsResolver) PermissionsForUser(ctx context.Context, userID uuid.UUID) (map[string]struct{}, error) {
	perms, err := r.userRepo.PermissionsForUser(ctx, r.pool, userID)
	if err != nil {
		return nil, err
	}
	// ALWAYS non-nil. An empty set and a missing set are different
	// semantics; diagnostics and tests are cleaner when "no permissions"
	// is explicit.
	result := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		result[p.Code] = struct{}{}
	}
	return result, nil
}
