package handler

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"UserManagementSystem/internal/apiresp"
	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/domain"
	"UserManagementSystem/internal/dto"
	"UserManagementSystem/internal/middleware"
	"UserManagementSystem/internal/service"
)

type userService interface {
	Create(ctx context.Context, in service.CreateUserInput) (*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	List(ctx context.Context, limit, offset int) ([]*domain.User, int, error)
	Update(ctx context.Context, id uuid.UUID, in service.UpdateUserInput) (*domain.User, error)
	SetActive(ctx context.Context, id uuid.UUID, active bool, actor *uuid.UUID) error
	SoftDelete(ctx context.Context, id uuid.UUID, actor *uuid.UUID) error
	AssignRole(ctx context.Context, userID, roleID uuid.UUID, actor *uuid.UUID) error
	RemoveRole(ctx context.Context, userID, roleID uuid.UUID, actor *uuid.UUID) error
	RolesForUser(ctx context.Context, userID uuid.UUID) ([]*domain.Role, error)
	PermissionsForUser(ctx context.Context, userID uuid.UUID) ([]*domain.Permission, error)
}

type UserHandler struct{ users userService }

func NewUserHandler(users userService) *UserHandler { return &UserHandler{users: users} }

// ---------- helpers (SRP: parameter parsing) ----------

func parsePathUUID(c *gin.Context, name string) (uuid.UUID, bool) {
	idStr := c.Param(name)
	id, err := uuid.Parse(idStr)
	if err != nil {
		apiresp.RespondBadRequest(c, c.GetString(middleware.RequestIDKey), name+" is not a uuid")
		return uuid.Nil, false
	}
	return id, true
}

func parsePagination(c *gin.Context) (limit, offset int, ok bool) {
	limit = 20
	offset = 0
	if v := c.Query("limit"); v != "" {
		n, err := atoiSafe(v)
		if err != nil || n < 1 || n > 100 {
			apiresp.RespondBadRequest(c, c.GetString(middleware.RequestIDKey), "limit must be 1-100")
			return 0, 0, false
		}
		limit = n
	}
	if v := c.GetString("offset"); v != "" { // will fail; use Query
	}
	if v := c.Query("offset"); v != "" {
		n, err := atoiSafe(v)
		if err != nil || n < 0 {
			apiresp.RespondBadRequest(c, c.GetString(middleware.RequestIDKey), "offset must be >= 0")
			return 0, 0, false
		}
		offset = n
	}
	return limit, offset, true
}

// atoiSafe keeps strconv out of the handler's top-level imports at the cost
// of one tiny helper. Alternative: import strconv directly.
func atoiSafe(s string) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, apperr.Wrap(apperr.ErrValidation, "not a number")
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

// actorFromContext returns the authenticated user's UUID (for audit), or nil
// if not set (should never happen on protected routes).
func actorFromContext(c *gin.Context) *uuid.UUID {
	if id, ok := middleware.UserIDFromContext(c); ok {
		return &id
	}
	return nil
}

// ---------- handlers ----------

func (h *UserHandler) Create(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	var req dto.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresp.RespondValidation(c, requestID)
		return
	}
	u, err := h.users.Create(c.Request.Context(), service.CreateUserInput{
		ActorUserID: actorFromContext(c),
		Email:       req.Email, Password: req.Password, FullName: req.FullName,
	})
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusCreated, toUserView(u))
}

func (h *UserHandler) List(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	limit, offset, ok := parsePagination(c)
	if !ok {
		return
	}
	users, total, err := h.users.List(c.Request.Context(), limit, offset)
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, toUserListResponse(users, total, limit, offset))
}

func (h *UserHandler) GetByID(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	u, err := h.users.GetByID(c.Request.Context(), id)
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, toUserView(u))
}

func (h *UserHandler) Update(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	var req dto.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresp.RespondValidation(c, requestID)
		return
	}
	u, err := h.users.Update(c.Request.Context(), id, service.UpdateUserInput{
		ActorUserID: actorFromContext(c),
		FullName:    req.FullName,
	})
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, toUserView(u))
}

func (h *UserHandler) SetStatus(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	var req dto.UpdateUserStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresp.RespondValidation(c, requestID)
		return
	}
	if err := h.users.SetActive(c.Request.Context(), id, *req.IsActive, actorFromContext(c)); err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *UserHandler) Delete(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	if err := h.users.SoftDelete(c.Request.Context(), id, actorFromContext(c)); err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *UserHandler) ListRoles(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	roles, err := h.users.RolesForUser(c.Request.Context(), id)
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, dto.UserRolesResponse{Roles: toRoleViews(roles)})
}

func (h *UserHandler) AssignRole(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	userID, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	var req dto.AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresp.RespondValidation(c, requestID)
		return
	}
	roleID, _ := uuid.Parse(req.RoleID) // binding:"uuid" guarantees parse
	if err := h.users.AssignRole(c.Request.Context(), userID, roleID, actorFromContext(c)); err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *UserHandler) RemoveRole(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	userID, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	roleID, ok := parsePathUUID(c, "roleId")
	if !ok {
		return
	}
	if err := h.users.RemoveRole(c.Request.Context(), userID, roleID, actorFromContext(c)); err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *UserHandler) ListPermissions(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	id, ok := parsePathUUID(c, "id")
	if !ok {
		return
	}
	perms, err := h.users.PermissionsForUser(c.Request.Context(), id)
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, dto.UserPermissionsResponse{Permissions: toPermissionViews(perms)})
}
