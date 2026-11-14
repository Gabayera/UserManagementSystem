package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/domain"
	"UserManagementSystem/internal/repository"
	"UserManagementSystem/internal/security"
)

// AuthService orchestrates registration, login, token rotation, and logout.
// The service is transport-agnostic: it does not know about HTTP, cookies, or
// handlers. Part 8 wires it into Gin.
type AuthService struct {
	pool       *pgxpool.Pool
	userRepo   repository.UserRepository
	tokenRepo  repository.RefreshTokenRepository
	roleRepo   repository.RoleRepository
	hasher     *security.PasswordHasher
	jwt        *security.JWTIssuer
	audit      AuditService
	accessTTL  time.Duration
	refreshTTL time.Duration

	// dummyHash is pre-computed at construction so unknown-email logins take
	// the same ~40 ms as wrong-password logins. Prevents account enumeration.
	dummyHash string
}

// Password bounds are measured in BYTES (that is what Argon2 hashes). The
// upper bound is NOT a bcrypt-style 72 limit; it only caps hashing cost.
const (
	minPasswordBytes = 8
	maxPasswordBytes = 128
)

type RegisterInput struct {
	Email    string
	Password string
	FullName string
}

type LoginInput struct {
	Email    string
	Password string
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int // access token TTL in seconds
}

type MeOutput struct {
	User        *domain.User
	Roles       []*domain.Role
	Permissions []*domain.Permission
}

func NewAuthService(
	pool *pgxpool.Pool,
	userRepo repository.UserRepository,
	tokenRepo repository.RefreshTokenRepository,
	roleRepo repository.RoleRepository,
	hasher *security.PasswordHasher,
	jwtIssuer *security.JWTIssuer,
	audit AuditService,
	accessTTL, refreshTTL time.Duration,
) (*AuthService, error) {
	if pool == nil {
		return nil, errors.New("auth: pool is nil")
	}
	if userRepo == nil || tokenRepo == nil || roleRepo == nil {
		return nil, errors.New("auth: repository dependency is nil")
	}
	if hasher == nil {
		return nil, errors.New("auth: hasher is nil")
	}
	if jwtIssuer == nil {
		return nil, errors.New("auth: jwt issuer is nil")
	}
	if audit == nil {
		return nil, errors.New("auth: audit is nil")
	}
	dummy, err := hasher.Hash(context.Background(), "dummy-password-for-timing-equalization")
	if err != nil {
		return nil, fmt.Errorf("auth: precompute dummy hash: %w", err)
	}
	return &AuthService{
		pool:       pool,
		userRepo:   userRepo,
		tokenRepo:  tokenRepo,
		roleRepo:   roleRepo,
		hasher:     hasher,
		jwt:        jwtIssuer,
		audit:      audit,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		dummyHash:  dummy,
	}, nil
}

// Register creates a user and assigns the default "user" role atomically.
// Password is hashed BEFORE opening the transaction so the 40 ms Argon2id
// computation doesn't hold a DB connection.
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (*domain.User, error) {
	clean, err := validateRegisterInput(in)
	if err != nil {
		return nil, err
	}

	hash, err := s.hasher.Hash(ctx, clean.Password)
	if err != nil {
		return nil, fmt.Errorf("auth: hash password: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, repository.MapError(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	u := domain.NewUser(clean.Email, hash, clean.FullName)
	if err := s.userRepo.Create(ctx, tx, u); err != nil {
		return nil, err
	}
	defaultRole, err := s.roleRepo.GetByName(ctx, tx, "user")
	if err != nil {
		return nil, fmt.Errorf("auth: get default role: %w", err)
	}
	if err := s.userRepo.AssignRole(ctx, tx, u.ID, defaultRole.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, repository.MapError(err)
	}

	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: &u.ID,
		Action:      "user.registered",
		EntityType:  "user",
		EntityID:    &u.ID,
		Metadata:    map[string]any{"email": u.Email},
	})
	return u, nil
}

// Login verifies credentials and issues a fresh token pair. Timing equalized
// for unknown-email vs wrong-password. Inactive users get 403 after password
// verification succeeds.
func (s *AuthService) Login(ctx context.Context, in LoginInput, ua, ip *string) (*TokenPair, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))

	// Reject absurd inputs before spending Argon2 time on them. Same error as
	// a wrong password so the bound itself isn't an oracle.
	if len(in.Password) > maxPasswordBytes || len(email) > 320 {
		return nil, apperr.ErrUnauthorized
	}

	user, err := s.userRepo.GetByEmail(ctx, s.pool, email)
	if err != nil {
		if errors.Is(err, apperr.ErrNotFound) {
			// Equalize timing — no-op result.
			_, _ = s.hasher.Verify(ctx, s.dummyHash, in.Password)
			s.auditBestEffort(ctx, AuditEntry{
				Action:   "auth.login.failed",
				Metadata: map[string]any{"reason": "unknown_email"},
			})
			return nil, apperr.ErrUnauthorized
		}
		return nil, err
	}

	ok, err := s.hasher.Verify(ctx, user.PasswordHash, in.Password)
	if err != nil {
		slog.Warn("auth_password_verify_error", "user_id", user.ID, "err", err)
		return nil, apperr.ErrUnauthorized
	}
	if !ok {
		s.auditBestEffort(ctx, AuditEntry{
			ActorUserID: &user.ID,
			Action:      "auth.login.failed",
			EntityType:  "user",
			EntityID:    &user.ID,
			Metadata:    map[string]any{"reason": "bad_password"},
		})
		return nil, apperr.ErrUnauthorized
	}
	if !user.IsActive {
		s.auditBestEffort(ctx, AuditEntry{
			ActorUserID: &user.ID,
			Action:      "auth.login.failed",
			EntityType:  "user",
			EntityID:    &user.ID,
			Metadata:    map[string]any{"reason": "inactive"},
		})
		return nil, apperr.ErrForbidden
	}

	access, jti, _, err := s.jwt.Sign(user.ID)
	if err != nil {
		return nil, err
	}
	raw, hash, err := security.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("auth: generate refresh: %w", err)
	}
	rt := &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		TokenHash: hash,
		FamilyID:  uuid.New(),
		ExpiresAt: time.Now().UTC().Add(s.refreshTTL),
		UserAgent: ua,
		IPAddress: ip,
	}
	if err := s.tokenRepo.Create(ctx, s.pool, rt); err != nil {
		return nil, err
	}

	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: &user.ID,
		Action:      "auth.login.success",
		EntityType:  "user",
		EntityID:    &user.ID,
		Metadata:    map[string]any{"jti": jti.String()},
		IPAddress:   ip,
	})
	return &TokenPair{
		AccessToken:  access,
		RefreshToken: raw,
		ExpiresIn:    int(s.accessTTL.Seconds()),
	}, nil
}

// Refresh rotates a live refresh token. On reuse (already-revoked token) the
// entire family is revoked. If the rotation races another legitimate refresh,
// Rotate returns ErrNotFound, which we treat identically to reuse.
//
// Documented trade-off: a legitimate retry of a refresh within the same second
// will look like reuse and log the user out. Accepted for security.
func (s *AuthService) Refresh(ctx context.Context, rawToken string, ua, ip *string) (*TokenPair, error) {
	if rawToken == "" {
		return nil, apperr.ErrUnauthorized
	}
	hash := security.HashRefreshToken(rawToken)

	old, err := s.tokenRepo.GetByHash(ctx, s.pool, hash)
	if err != nil {
		if errors.Is(err, apperr.ErrNotFound) {
			return nil, apperr.ErrUnauthorized
		}
		return nil, err
	}

	if old.RevokedAt != nil {
		if err := s.tokenRepo.RevokeByFamily(ctx, s.pool, old.FamilyID); err != nil {
			slog.Warn("auth_family_revoke_failed", "family_id", old.FamilyID, "err", err)
		}
		s.auditBestEffort(ctx, AuditEntry{
			ActorUserID: &old.UserID,
			Action:      "auth.refresh.reuse_detected",
			EntityType:  "refresh_token",
			Metadata:    map[string]any{"family_id": old.FamilyID.String()},
			IPAddress:   ip,
		})
		return nil, apperr.ErrUnauthorized
	}

	if time.Now().After(old.ExpiresAt) {
		s.auditBestEffort(ctx, AuditEntry{
			ActorUserID: &old.UserID,
			Action:      "auth.refresh.expired",
			Metadata:    map[string]any{"family_id": old.FamilyID.String()},
		})
		return nil, apperr.ErrUnauthorized
	}

	// The user must still exist and be active. Soft-deleted users surface as
	// ErrNotFound; deactivated users have IsActive=false. In both cases the
	// whole family is revoked so the token cannot be retried later.
	user, err := s.userRepo.GetByID(ctx, s.pool, old.UserID)
	if err != nil {
		if errors.Is(err, apperr.ErrNotFound) {
			_ = s.tokenRepo.RevokeByFamily(ctx, s.pool, old.FamilyID)
			return nil, apperr.ErrUnauthorized
		}
		return nil, err
	}
	if !user.IsActive {
		_ = s.tokenRepo.RevokeByFamily(ctx, s.pool, old.FamilyID)
		s.auditBestEffort(ctx, AuditEntry{
			ActorUserID: &old.UserID,
			Action:      "auth.refresh.denied",
			EntityType:  "user",
			EntityID:    &old.UserID,
			Metadata:    map[string]any{"reason": "inactive"},
			IPAddress:   ip,
		})
		return nil, apperr.ErrUnauthorized
	}

	newRaw, newHash, err := security.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("auth: generate refresh: %w", err)
	}
	newTok := &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    old.UserID,
		TokenHash: newHash,
		FamilyID:  old.FamilyID,
		ExpiresAt: time.Now().UTC().Add(s.refreshTTL),
		UserAgent: ua,
		IPAddress: ip,
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, repository.MapError(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.tokenRepo.Rotate(ctx, tx, old.ID, newTok); err != nil {
		if errors.Is(err, apperr.ErrNotFound) {
			// Race: another request already rotated. Rollback our tx, kill
			// the whole family (outside tx — our tx is being rolled back).
			_ = tx.Rollback(ctx)
			_ = s.tokenRepo.RevokeByFamily(ctx, s.pool, old.FamilyID)
			s.auditBestEffort(ctx, AuditEntry{
				ActorUserID: &old.UserID,
				Action:      "auth.refresh.reuse_detected",
				Metadata:    map[string]any{"family_id": old.FamilyID.String(), "reason": "race"},
			})
			return nil, apperr.ErrUnauthorized
		}
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, repository.MapError(err)
	}

	access, _, _, err := s.jwt.Sign(old.UserID)
	if err != nil {
		return nil, err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: &old.UserID,
		Action:      "auth.refresh",
		EntityType:  "refresh_token",
		IPAddress:   ip,
	})
	return &TokenPair{
		AccessToken:  access,
		RefreshToken: newRaw,
		ExpiresIn:    int(s.accessTTL.Seconds()),
	}, nil
}

// Logout revokes the presented refresh token. Idempotent — logging out an
// already-revoked or nonexistent token is a no-op returning nil.
func (s *AuthService) Logout(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return nil
	}
	hash := security.HashRefreshToken(rawToken)
	tok, err := s.tokenRepo.GetByHash(ctx, s.pool, hash)
	if err != nil {
		if errors.Is(err, apperr.ErrNotFound) {
			return nil
		}
		return err
	}
	if err := s.tokenRepo.RevokeByID(ctx, s.pool, tok.ID); err != nil {
		return err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: &tok.UserID,
		Action:      "auth.logout",
	})
	return nil
}

// LogoutAll revokes every live refresh token for the user.
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	if err := s.tokenRepo.RevokeAllForUser(ctx, s.pool, userID); err != nil {
		return err
	}
	s.auditBestEffort(ctx, AuditEntry{
		ActorUserID: &userID,
		Action:      "auth.logout_all",
	})
	return nil
}

// Me returns the user with roles and permissions resolved from the DB. This is
// the identity check the auth middleware will call via the handler in Part 8.
func (s *AuthService) Me(ctx context.Context, userID uuid.UUID) (*MeOutput, error) {
	user, err := s.userRepo.GetByID(ctx, s.pool, userID)
	if err != nil {
		return nil, err
	}
	// A still-valid access token must not keep working for a deactivated user.
	if !user.IsActive {
		return nil, apperr.ErrUnauthorized
	}
	roles, err := s.userRepo.RolesForUser(ctx, s.pool, userID)
	if err != nil {
		return nil, err
	}
	perms, err := s.userRepo.PermissionsForUser(ctx, s.pool, userID)
	if err != nil {
		return nil, err
	}
	return &MeOutput{User: user, Roles: roles, Permissions: perms}, nil
}

func (s *AuthService) auditBestEffort(ctx context.Context, entry AuditEntry) {
	if err := s.audit.Log(ctx, entry); err != nil {
		slog.Warn("audit_log_failed", "action", entry.Action, "err", err)
	}
}

func validateRegisterInput(in RegisterInput) (RegisterInput, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	fullName := strings.TrimSpace(in.FullName)

	if email == "" || !strings.Contains(email, "@") || len(email) > 320 {
		return RegisterInput{}, apperr.Wrap(apperr.ErrValidation, "invalid email")
	}
	if fullName == "" || len(fullName) > 100 {
		return RegisterInput{}, apperr.Wrap(apperr.ErrValidation, "invalid full_name")
	}
	if len(in.Password) < minPasswordBytes || len(in.Password) > maxPasswordBytes {
		return RegisterInput{}, apperr.Wrap(apperr.ErrValidation,
			"password must be %d-%d bytes", minPasswordBytes, maxPasswordBytes)
	}
	return RegisterInput{Email: email, Password: in.Password, FullName: fullName}, nil
}
