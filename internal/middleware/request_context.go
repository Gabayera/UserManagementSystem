package middleware

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"UserManagementSystem/internal/service"
)

// RequestContext captures request_id + client_ip from Gin into the standard
// context.Context so that services can read them without importing gin.
// MUST run after RequestID() (needs request_id) and before Auth() (Auth will
// update it with user_id via SetAuthenticatedUser).
func RequestContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		rc := service.RequestContext{
			RequestID: c.GetString(RequestIDKey),
			IPAddress: c.ClientIP(),
		}
		ctx := service.WithRequestContext(c.Request.Context(), rc)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// SetAuthenticatedUser updates the RequestContext in the underlying
// context.Context with the authenticated user. Called from Auth middleware
// after JWT verification. If RequestContext() middleware is missing from the
// chain, logs a warning — that's a configuration bug that would silently
// strip user attribution from every audit row on protected routes.
func SetAuthenticatedUser(c *gin.Context, userID uuid.UUID) {
	rc, ok := service.RequestContextFromContext(c.Request.Context())
	if !ok {
		slog.Warn("request_context_missing",
			"request_id", c.GetString(RequestIDKey),
			"reason", "Auth ran but RequestContext middleware did not — audit will lack user attribution",
		)
		return
	}
	rc.UserID = &userID
	ctx := service.WithRequestContext(c.Request.Context(), rc)
	c.Request = c.Request.WithContext(ctx)
}
