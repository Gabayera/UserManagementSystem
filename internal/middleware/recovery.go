package middleware

import (
	"io"
	"log/slog"
	"runtime/debug"

	"github.com/gin-gonic/gin"

	"UserManagementSystem/internal/apiresp"
)

// Recovery converts panics into 500 responses through apiresp — the same
// choke point every other error uses. io.Discard suppresses Gin's default
// panic printer; we emit one structured slog line and one JSON body instead.
func Recovery() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, recovered any) {
		requestID := c.GetString(RequestIDKey)
		slog.Error("panic_recovered",
			"request_id", requestID,
			"path", c.FullPath(),
			"panic", recovered,
			"stack", string(debug.Stack()),
		)
		apiresp.RespondInternal(c, requestID)
		c.Abort()
	})
}
