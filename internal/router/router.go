package router

import (
	"github.com/gin-gonic/gin"

	"UserManagementSystem/internal/handler"
	"UserManagementSystem/internal/middleware"
)

// New assembles the engine. Middleware order is THE most load-bearing line
// in this file — see ADR-011 (revised). RequestID → Logger → Recovery are
// global. Auth runs only on the protected group.
func New(
	health *handler.HealthHandler,
	auth *handler.AuthHandler,
	verifier middleware.TokenVerifier,
) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	_ = r.SetTrustedProxies(nil)

	r.Use(middleware.RequestID())
	r.Use(middleware.Logger())
	r.Use(middleware.Recovery())

	r.GET("/healthz", health.Healthz)
	r.GET("/readyz", health.Readyz)

	api := r.Group("/api/v1")

	// Public auth endpoints — no Bearer required.
	authPublic := api.Group("/auth")
	authPublic.POST("/register", auth.Register)
	authPublic.POST("/login", auth.Login)
	authPublic.POST("/refresh", auth.Refresh)
	authPublic.POST("/logout", auth.Logout)

	// Protected auth endpoints — Bearer required.
	authProtected := api.Group("/auth")
	authProtected.Use(middleware.Auth(verifier))
	authProtected.POST("/logout-all", auth.LogoutAll)
	authProtected.GET("/me", auth.Me)

	return r
}
