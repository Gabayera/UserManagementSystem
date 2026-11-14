package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// Logger emits exactly one structured log line per completed request.
//
// Ordering note (Part 2 correction): Logger runs OUTSIDE Recovery so it sees
// the final status Recovery writes on a panic. Its "after" code must be in a
// defer, otherwise it never runs when c.Next() panics.
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		defer func() {
			slog.Info("http_request",
				"method", c.Request.Method,
				// path is the route TEMPLATE (/users/:id), never the raw path —
				// raw paths explode log cardinality and can include user input.
				"path", c.FullPath(),
				"status", c.Writer.Status(),
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", c.GetString(RequestIDKey),
				"user_id", userIDString(c),
				"client_ip", c.ClientIP())
		}()
		c.Next()
	}
}

// userIDString reads the typed user ID from context. Returns "" when the
// request is unauthenticated. Never logs the UUID as a raw interface{} —
// it's always the canonical 36-char string.
func userIDString(c *gin.Context) string {
	if id, ok := UserIDFromContext(c); ok {
		return id.String()
	}
	return ""
}
