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

type permissionService interface {
	Create(ctx context.Context, in service.CreatePermissionInput) (*domain.Permission, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Permission, error)
	List(ctx context.Context, limit, offset int) ([]*domain.Permission, int, error)
	Update(ctx context.Context, id uuid.UUID, in service.UpdatePermissionInput) (*domain.Permission, error)
	Delete(ctx context.Context, id uuid.UUID, actor *uuid.UUID) error
}

type PermissionHandler struct{ perms permissionService }

func NewPermissionHandler(perms permissionService) *PermissionHandler {
	return &PermissionHandler{perms: perms}
}

func (h *PermissionHandler) Create(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	var req dto.CreatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresp.RespondValidation(c, requestID)
		return
	}
	p, err := h.perms.Create(c.Request.Context(), service.CreatePermissionInput{
		ActorUserID: actorFromContext(c),
		Code:        req.Code, Description: req.Description,
	})
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusCreated, toPermissionView(p))
}

func (h *PermissionHandler) List(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	limit, offset, ok := parsePagination(c)
	if !ok {
		return
	}
	perms, total, err := h.perms.List(c.Request.Context(), limit, offset)
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, toPermissionListResponse(perms, total, limit, offset))
}

func (h *PermissionHandler) GetByID(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	p, err := h.perms.GetByID(c.Request.Context(), id)
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, toPermissionView(p))
}

func (h *PermissionHandler) Update(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	var req dto.UpdatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresp.RespondValidation(c, requestID)
		return
	}
	p, err := h.perms.Update(c.Request.Context(), id, service.UpdatePermissionInput{
		ActorUserID: actorFromContext(c),
		Description: req.Description,
	})
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, toPermissionView(p))
}

func (h *PermissionHandler) Delete(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	if err := h.perms.Delete(c.Request.Context(), id, actorFromContext(c)); err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.Status(http.StatusNoContent)
}
