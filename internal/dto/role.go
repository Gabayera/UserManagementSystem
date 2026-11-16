package dto

type RoleListResponse struct {
	Roles  []RoleView `json:"roles"`
	Total  int        `json:"total"`
	Limit  int        `json:"limit"`
	Offset int        `json:"offset"`
}

type CreateRoleRequest struct {
	Name        string  `json:"name"        binding:"required,min=1,max=100"`
	Description *string `json:"description"`
}

type UpdateRoleRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type AssignPermissionRequest struct {
	PermissionID string `json:"permission_id" binding:"required,uuid"`
}

type RolePermissionsResponse struct {
	Permissions []PermissionView `json:"permissions"`
}
