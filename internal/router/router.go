package router

import (
	"github.com/gin-gonic/gin"

	"UserManagementSystem/internal/apiresp"
	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/handler"
	"UserManagementSystem/internal/middleware"
	"UserManagementSystem/internal/service"
)

// New assembles the engine. The route table IS the authorization policy.
// Every protected route carries an explicit RequirePermission gate; the only
// routes without one are public (health/auth endpoints) or auth-only (me,
// logout-all). If you add a route and forget RequirePermission, a code review
// must catch it — that's the design.
func New(
	health *handler.HealthHandler,
	auth *handler.AuthHandler,
	user *handler.UserHandler,
	role *handler.RoleHandler,
	perm *handler.PermissionHandler,
	verifier middleware.TokenVerifier,
	resolver service.PermissionsResolver,
) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	_ = r.SetTrustedProxies(nil)

	r.Use(middleware.RequestID())
	r.Use(middleware.Logger())
	r.Use(middleware.Recovery())
	r.Use(middleware.RequestContext())

	// Ops probes — public, outside /api/v1.
	r.GET("/healthz", health.Healthz)
	r.GET("/readyz", health.Readyz)

	api := r.Group("/api/v1")

	// ---------- public auth ----------
	authPublic := api.Group("/auth")
	authPublic.POST("/register", auth.Register)
	authPublic.POST("/login", auth.Login)
	authPublic.POST("/refresh", auth.Refresh)
	authPublic.POST("/logout", auth.Logout)

	// ---------- auth-only (no permission required) ----------
	authOnly := api.Group("/auth")
	authOnly.Use(middleware.Auth(verifier))
	authOnly.POST("/logout-all", auth.LogoutAll)
	authOnly.GET("/me", auth.Me)

	// ---------- permission-gated ----------
	protected := api.Group("")
	protected.Use(middleware.Auth(verifier))

	req := func(code string) gin.HandlerFunc {
		return middleware.RequirePermission(resolver, code)
	}

	// Users
	protected.GET("/users", req("user.read.all"), user.List)
	protected.POST("/users", req("user.create"), user.Create)
	protected.GET("/users/:id", req("user.read.all"), user.GetByID)
	protected.PATCH("/users/:id", req("user.update"), user.Update)
	protected.DELETE("/users/:id", req("user.delete"), user.Delete)
	protected.PATCH("/users/:id/status", req("user.update"), user.SetStatus)
	protected.GET("/users/:id/roles", req("user.read.all"), user.ListRoles)
	protected.POST("/users/:id/roles", req("user.update"), user.AssignRole)
	protected.DELETE("/users/:id/roles/:roleId", req("user.update"), user.RemoveRole)
	protected.GET("/users/:id/permissions", req("user.read.all"), user.ListPermissions)

	// Roles
	protected.GET("/roles", req("role.read"), role.List)
	protected.POST("/roles", req("role.create"), role.Create)
	protected.GET("/roles/:id", req("role.read"), role.GetByID)
	protected.PATCH("/roles/:id", req("role.update"), role.Update)
	protected.DELETE("/roles/:id", req("role.delete"), role.Delete)
	protected.GET("/roles/:id/permissions", req("role.read"), role.ListPermissions)
	protected.POST("/roles/:id/permissions", req("role.update"), role.AddPermission)
	protected.DELETE("/roles/:id/permissions/:permissionId", req("role.update"), role.RemovePermission)

	// Permissions
	protected.GET("/permissions", req("permission.read"), perm.List)
	protected.POST("/permissions", req("permission.create"), perm.Create)
	protected.GET("/permissions/:id", req("permission.read"), perm.GetByID)
	protected.PATCH("/permissions/:id", req("permission.update"), perm.Update)
	protected.DELETE("/permissions/:id", req("permission.delete"), perm.Delete)

	// NoRoute — 404 in our envelope (TD-07). Also feeds TD-06: logger will
	// see path="" and use "unmatched".
	r.NoRoute(func(c *gin.Context) {
		apiresp.Respond(c, apperr.ErrNotFound, c.GetString(middleware.RequestIDKey))
	})

	return r
}
