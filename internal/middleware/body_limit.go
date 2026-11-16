package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// DefaultMaxBodyBytes is the per-request body cap for JSON API endpoints.
const DefaultMaxBodyBytes int64 = 64 << 10 // 64 KiB

// BodyLimit caps the request body. Gin has NO default limit, so without this
// a client can stream megabytes into ShouldBindJSON (and into Argon2 via the
// password field). Reads past the cap fail with *http.MaxBytesError, which
// ShouldBindJSON surfaces as a bind error -> 422 from the handler.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Fast path: honest clients declare Content-Length.
		if c.Request.ContentLength > maxBytes {
			c.AbortWithStatus(http.StatusRequestEntityTooLarge)
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}
