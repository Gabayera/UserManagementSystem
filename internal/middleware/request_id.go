package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const maxRequestIDLen = 64

// RequestID guarantees every request carries a request ID both in the Gin
// context and in the X-Request-ID response header. A client-supplied ID is
// preserved (tracing across services) ONLY if it is short and made of safe
// characters; otherwise it is discarded and a fresh UUID is generated. This
// prevents log injection and oversized headers being echoed back.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if !validRequestID(id) {
			id = uuid.NewString()
		}
		c.Set(RequestIDKey, id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}

func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}
