package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// Logger emits exactly one structured log line per completed request.
//
// CRITICAL: slog.Info MUST live inside the deferred block, AFTER c.Next()
// has returned. If placed above c.Next() it reads stale values
// (status=200, user_id="", duration_ms=0) — TD-21. The defer also runs
// during panic unwinding so panicked requests get their status=500 line
// before Recovery writes the final body.
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		defer func() {
			path := c.FullPath()
			if path == "" {
				// NoRoute fired — no template exists. Use a stable
				// marker so 404s don't disappear into log noise.
				path = "unmatched"
			}
			slog.Info("http_request",
				"method", c.Request.Method,
				"path", path,
				"status", c.Writer.Status(),
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", c.GetString(RequestIDKey),
				"user_id", userIDString(c),
				"client_ip", c.ClientIP(),
			)
		}()

		c.Next()
	}
}

// userIDString reads the typed uuid.UUID from the Gin context. Gin's
// GetString returns "" when the stored value is a uuid.UUID (not a string),
// which would silently strip user_id from every authenticated log line.
// This helper type-asserts via UserIDFromContext and formats canonically.
func userIDString(c *gin.Context) string {
	if id, ok := UserIDFromContext(c); ok {
		return id.String()
	}
	return ""
}
