package dto

type PermissionListResponse struct {
	Permissions []PermissionView `json:"permissions"`
	Total       int              `json:"total"`
	Limit       int              `json:"limit"`
	Offset      int              `json:"offset"`
}

type CreatePermissionRequest struct {
	Code        string  `json:"code"        binding:"required,min=1,max=100"`
	Description *string `json:"description"`
}

type UpdatePermissionRequest struct {
	Description *string `json:"description"`
}
