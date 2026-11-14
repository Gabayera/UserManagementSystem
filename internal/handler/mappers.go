package handler

import (
	"time"

	"UserManagementSystem/internal/domain"
	"UserManagementSystem/internal/dto"
	"UserManagementSystem/internal/service"
)

const rfc3339 = time.RFC3339

// Pure domain → DTO mappers. No I/O, no gin, no service calls. Handlers
// compose these; the dto package never imports domain.

func toRegisterResponse(u *domain.User) dto.RegisterResponse {
	return dto.RegisterResponse{
		ID:        u.ID.String(),
		Email:     u.Email,
		FullName:  u.FullName,
		CreatedAt: u.CreatedAt.UTC().Format(rfc3339),
	}
}

func toLoginResponse(p *service.TokenPair) dto.LoginResponse {
	return dto.LoginResponse{
		AccessToken:  p.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    p.ExpiresIn,
		RefreshToken: p.RefreshToken,
	}
}

// toRefreshResponse echoes the rotated refresh token only for body-based
// (native) clients — see dto.RefreshResponse.
func toRefreshResponse(p *service.TokenPair, includeRefreshToken bool) dto.RefreshResponse {
	resp := dto.RefreshResponse{
		AccessToken: p.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   p.ExpiresIn,
	}
	if includeRefreshToken {
		resp.RefreshToken = p.RefreshToken
	}
	return resp
}

func toUserView(u *domain.User) dto.UserView {
	return dto.UserView{
		ID:        u.ID.String(),
		Email:     u.Email,
		FullName:  u.FullName,
		IsActive:  u.IsActive,
		CreatedAt: u.CreatedAt.UTC().Format(rfc3339),
		UpdatedAt: u.UpdatedAt.UTC().Format(rfc3339),
	}
}

func toRoleView(r *domain.Role) dto.RoleView {
	return dto.RoleView{ID: r.ID.String(), Name: r.Name, Description: r.Description}
}

func toPermissionView(p *domain.Permission) dto.PermissionView {
	return dto.PermissionView{ID: p.ID.String(), Code: p.Code, Description: p.Description}
}

func toMeResponse(out *service.MeOutput) dto.MeResponse {
	roles := make([]dto.RoleView, 0, len(out.Roles))
	for _, r := range out.Roles {
		roles = append(roles, toRoleView(r))
	}
	perms := make([]dto.PermissionView, 0, len(out.Permissions))
	for _, p := range out.Permissions {
		perms = append(perms, toPermissionView(p))
	}
	return dto.MeResponse{
		User:        toUserView(out.User),
		Roles:       roles,
		Permissions: perms,
	}
}
