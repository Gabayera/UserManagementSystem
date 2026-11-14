package middleware

import (
	"log/slog"

	"github.com/gin-gonic/gin"

	"UserManagementSystem/internal/apiresp"
	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/service"
)

// RequirePermission gates a route on the caller having a specific permission
// code. It MUST run after Auth — Auth sets user_id; this middleware reads it.
//
// Fail-closed rule: if the resolver errors, respond 5xx and abort. Never call
// c.Next() on error — a resolver outage must not become an authorization bypass.
//
// 401 vs 403: 401 means "who are you?" (Auth's job). 403 means "I know who you
// are, and you can't do this" (this middleware's job).
func RequirePermission(resolver service.PermissionsResolver, code string) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetString(RequestIDKey)

		userID, ok := UserIDFromContext(c)
		if !ok {
			// Middleware-order bug: Auth didn't run before RequirePermission.
			// This is our misconfiguration, not a client problem — 500, not 401.
			slog.Error("authz_order_bug",
				"request_id", requestID,
				"path", c.FullPath(),
				"reason", "UserIDFromContext missing — Auth not chained before RequirePermission",
			)
			apiresp.RespondInternal(c, requestID)
			c.Abort()
			return
		}

		perms, err := resolver.PermissionsForUser(c.Request.Context(), userID)
		if err != nil {
			// Fail-closed: broken resolver must not wave requests through.
			slog.Error("authz_resolver_failed",
				"request_id", requestID,
				"user_id", userID,
				"err", err,
			)
			apiresp.Respond(c, err, requestID)
			c.Abort()
			return
		}

		if _, has := perms[code]; !has {
			apiresp.Respond(c, apperr.ErrForbidden, requestID)
			c.Abort()
			return
		}

		c.Next()
	}
}
