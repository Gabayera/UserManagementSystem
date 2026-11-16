package handler

import (
	"time"

	"UserManagementSystem/internal/domain"
	"UserManagementSystem/internal/dto"
	"UserManagementSystem/internal/service"
)

const rfc3339 = time.RFC3339

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

func toRefreshResponse(p *service.TokenPair) dto.RefreshResponse {
	return dto.RefreshResponse{
		AccessToken: p.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   p.ExpiresIn,
	}
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
	return dto.MeResponse{
		User:        toUserView(out.User),
		Roles:       toRoleViews(out.Roles),
		Permissions: toPermissionViews(out.Permissions),
	}
}

func toUserListResponse(users []*domain.User, total, limit, offset int) dto.UserListResponse {
	views := make([]dto.UserView, 0, len(users))
	for _, u := range users {
		views = append(views, toUserView(u))
	}
	return dto.UserListResponse{Users: views, Total: total, Limit: limit, Offset: offset}
}

func toRoleListResponse(roles []*domain.Role, total, limit, offset int) dto.RoleListResponse {
	views := make([]dto.RoleView, 0, len(roles))
	for _, r := range roles {
		views = append(views, toRoleView(r))
	}
	return dto.RoleListResponse{Roles: views, Total: total, Limit: limit, Offset: offset}
}

func toPermissionListResponse(perms []*domain.Permission, total, limit, offset int) dto.PermissionListResponse {
	views := make([]dto.PermissionView, 0, len(perms))
	for _, p := range perms {
		views = append(views, toPermissionView(p))
	}
	return dto.PermissionListResponse{Permissions: views, Total: total, Limit: limit, Offset: offset}
}

func toRoleViews(rs []*domain.Role) []dto.RoleView {
	out := make([]dto.RoleView, 0, len(rs))
	for _, r := range rs {
		out = append(out, toRoleView(r))
	}
	return out
}

func toPermissionViews(ps []*domain.Permission) []dto.PermissionView {
	out := make([]dto.PermissionView, 0, len(ps))
	for _, p := range ps {
		out = append(out, toPermissionView(p))
	}
	return out
}
