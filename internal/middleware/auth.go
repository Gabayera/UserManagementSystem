package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"UserManagementSystem/internal/apiresp"
	"UserManagementSystem/internal/apperr"
)

type TokenVerifier interface {
	Verify(raw string) (userID uuid.UUID, jti uuid.UUID, err error)
}

func Auth(verifier TokenVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetString(RequestIDKey)

		header := c.GetHeader("Authorization")
		if header == "" {
			apiresp.Respond(c, apperr.ErrUnauthorized, requestID)
			c.Abort()
			return
		}

		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			apiresp.Respond(c, apperr.ErrUnauthorized, requestID)
			c.Abort()
			return
		}

		userID, jti, err := verifier.Verify(parts[1])
		if err != nil {
			apiresp.Respond(c, apperr.ErrUnauthorized, requestID)
			c.Abort()
			return
		}

		c.Set(UserIDKey, userID)
		c.Set(JTIKey, jti)
		SetAuthenticatedUser(c, userID) // Part 12: propagate to context.Context for audit
		c.Next()
	}
}

func UserIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get(UserIDKey)
	if !ok {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}

func JTIFromContext(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get(JTIKey)
	if !ok {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}
