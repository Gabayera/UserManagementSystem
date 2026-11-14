package dto

// Request DTOs. Tags are the first line of validation; business rules
// (uniqueness, password policy) live in the service.
type RegisterRequest struct {
	Email    string `json:"email"     binding:"required,email,max=320"`
	Password string `json:"password"  binding:"required,min=8"`
	FullName string `json:"full_name" binding:"required,min=1,max=100"`
}

// LoginRequest deliberately has no `email`/`min` binding tags.
// Malformed email on login is a credential failure (401), not a request
// validation error (422) — and telling an attacker the min password length
// is an information leak.
type LoginRequest struct {
	Email    string `json:"email"    binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RefreshRequest is the optional body form of the refresh token for native
// clients that can't use HttpOnly cookies. Browsers use the cookie; body is
// only a fallback.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RegisterResponse has NO password, NO password_hash, NO tokens.
type RegisterResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FullName  string `json:"full_name"`
	CreatedAt string `json:"created_at"`
}

// LoginResponse includes the refresh token in the body AND sets it as a
// cookie (ADR-006). Both transports carry the same value.
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse carries the rotated refresh token in the body ONLY when the
// client presented its old token in the body (native clients without cookie
// support). Browser clients get the new token solely via the HttpOnly cookie.
// Without this, a native client would be left holding a revoked token and the
// next refresh would be treated as reuse, killing the whole token family.
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// UserView deliberately omits password_hash and deleted_at. These fields
// must never appear on the wire.
type UserView struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FullName  string `json:"full_name"`
	IsActive  bool   `json:"is_active"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type RoleView struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

type PermissionView struct {
	ID          string  `json:"id"`
	Code        string  `json:"code"`
	Description *string `json:"description,omitempty"`
}

type MeResponse struct {
	User        UserView         `json:"user"`
	Roles       []RoleView       `json:"roles"`
	Permissions []PermissionView `json:"permissions"`
}
