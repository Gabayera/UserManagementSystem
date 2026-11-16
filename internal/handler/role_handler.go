package handler

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"UserManagementSystem/internal/apiresp"
	"UserManagementSystem/internal/domain"
	"UserManagementSystem/internal/dto"
	"UserManagementSystem/internal/middleware"
	"UserManagementSystem/internal/service"
)

type roleService interface {
	Create(ctx context.Context, in service.CreateRoleInput) (*domain.Role, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Role, error)
	List(ctx context.Context, limit, offset int) ([]*domain.Role, int, error)
	Update(ctx context.Context, id uuid.UUID, in service.UpdateRoleInput) (*domain.Role, error)
	SoftDelete(ctx context.Context, id uuid.UUID, actor *uuid.UUID) error
	AddPermission(ctx context.Context, roleID, permissionID uuid.UUID, actor *uuid.UUID) error
	RemovePermission(ctx context.Context, roleID, permissionID uuid.UUID, actor *uuid.UUID) error
	ListPermissions(ctx context.Context, roleID uuid.UUID) ([]*domain.Permission, error)
}

type RoleHandler struct{ roles roleService }

func NewRoleHandler(roles roleService) *RoleHandler { return &RoleHandler{roles: roles} }

func (h *RoleHandler) Create(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	var req dto.CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresp.RespondValidation(c, requestID)
		return
	}
	r, err := h.roles.Create(c.Request.Context(), service.CreateRoleInput{
		ActorUserID: actorFromContext(c),
		Name:        req.Name, Description: req.Description,
	})
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusCreated, toRoleView(r))
}

func (h *RoleHandler) List(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	limit, offset, ok := parsePagination(c)
	if !ok {
		return
	}
	roles, total, err := h.roles.List(c.Request.Context(), limit, offset)
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, toRoleListResponse(roles, total, limit, offset))
}

func (h *RoleHandler) GetByID(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	r, err := h.roles.GetByID(c.Request.Context(), id)
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, toRoleView(r))
}

func (h *RoleHandler) Update(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	var req dto.UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresp.RespondValidation(c, requestID)
		return
	}
	r, err := h.roles.Update(c.Request.Context(), id, service.UpdateRoleInput{
		ActorUserID: actorFromContext(c),
		Name:        req.Name, Description: req.Description,
	})
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, toRoleView(r))
}

func (h *RoleHandler) Delete(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	if err := h.roles.SoftDelete(c.Request.Context(), id, actorFromContext(c)); err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *RoleHandler) ListPermissions(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	perms, err := h.roles.ListPermissions(c.Request.Context(), id)
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, dto.RolePermissionsResponse{Permissions: toPermissionViews(perms)})
}

func (h *RoleHandler) AddPermission(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	roleID, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	var req dto.AssignPermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresp.RespondValidation(c, requestID)
		return
	}
	permID, _ := uuid.Parse(req.PermissionID)
	if err := h.roles.AddPermission(c.Request.Context(), roleID, permID, actorFromContext(c)); err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *RoleHandler) RemovePermission(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	roleID, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	permID, ok := parsePathUUID(c, "permissionId")
	if !ok {
		return
	}
	if err := h.roles.RemovePermission(c.Request.Context(), roleID, permID, actorFromContext(c)); err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.Status(http.StatusNoContent)
}
