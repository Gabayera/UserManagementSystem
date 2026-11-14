package router

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"UserManagementSystem/internal/handler"
	"UserManagementSystem/internal/middleware"
)

// Options carries environment-derived router settings.
type Options struct {
	// Prod selects gin.ReleaseMode; otherwise gin.DebugMode is used.
	Prod bool
	// TrustedProxies are the proxy IPs/CIDRs whose X-Forwarded-For is trusted.
	// Empty/nil = trust nobody, so c.ClientIP() is the direct TCP peer.
	TrustedProxies []string
}

// New assembles the engine. Middleware order is THE most load-bearing line
// in this file — see ADR-011 (revised). RequestID → Logger → Recovery →
// BodyLimit are global. Auth runs only on the protected group.
func New(
	health *handler.HealthHandler,
	auth *handler.AuthHandler,
	verifier middleware.TokenVerifier,
	opts Options,
) (*gin.Engine, error) {
	if opts.Prod {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}
	r := gin.New()
	// Passing nil trusts nobody; passing a list trusts exactly those proxies.
	if err := r.SetTrustedProxies(opts.TrustedProxies); err != nil {
		return nil, fmt.Errorf("router: invalid trusted proxies: %w", err)
	}

	r.Use(middleware.RequestID())
	r.Use(middleware.Logger())
	r.Use(middleware.Recovery())
	r.Use(middleware.BodyLimit(middleware.DefaultMaxBodyBytes))

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

	return r, nil
}
