package middleware

import (
	"github.com/google/uuid"

	"github.com/gin-gonic/gin"
)

// RequestID guarantees every request carries a request ID both in the Gin
// context and in the X-Request-ID response header. If the client supplies
// one, it is preserved (tracing across services); otherwise we generate one.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		c.Set(RequestIDKey, id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}