package dto

type UserListResponse struct {
	Users  []UserView `json:"users"`
	Total  int        `json:"total"`
	Limit  int        `json:"limit"`
	Offset int        `json:"offset"`
}

type CreateUserRequest struct {
	Email    string `json:"email"     binding:"required,email,max=320"`
	Password string `json:"password"  binding:"required,min=8,max=72"`
	FullName string `json:"full_name" binding:"required,min=1,max=100"`
}

type UpdateUserRequest struct {
	FullName *string `json:"full_name"`
}

type UpdateUserStatusRequest struct {
	IsActive *bool `json:"is_active" binding:"required"`
}

type AssignRoleRequest struct {
	RoleID string `json:"role_id" binding:"required,uuid"`
}

type UserRolesResponse struct {
	Roles []RoleView `json:"roles"`
}

type UserPermissionsResponse struct {
	Permissions []PermissionView `json:"permissions"`
}
