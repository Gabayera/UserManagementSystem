package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

// Recovery converts panics into 500 responses with our error envelope and a
// structured slog line. io.Discard suppresses Gin's default printer, which
// dumps a raw stack trace to stderr — we want structured logs, not raw dumps.
func Recovery() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, recovered any) {
		slog.Error("panic_recovered",
			"request_id", c.GetString(RequestIDKey),
			"path", c.FullPath(),
			"panic", recovered,
			// Stack is logged server-side only; never returned to the client.
			"stack", string(debug.Stack()),
		)

		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": gin.H{
				"code":    "internal",
				"message": "internal error",
			},
		})
	})
}