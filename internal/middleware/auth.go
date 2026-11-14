package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"UserManagementSystem/internal/apiresp"
	"UserManagementSystem/internal/apperr"
)

// TokenVerifier is the ONLY thing the auth middleware needs. Defined at the
// consumer (DIP) so middleware does not import internal/security, does not
// know about JWT claim structures, and can be unit-tested with a fake.
type TokenVerifier interface {
	Verify(raw string) (userID uuid.UUID, jti uuid.UUID, err error)
}

// Auth is the stateless authentication middleware. It verifies the Bearer
// token, sets user_id + jti on the context, and continues. It makes NO DB
// calls — RBAC is Part 10's job.
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
			// Do NOT log at INFO — a bad token is normal traffic noise.
			// Do NOT return the reason to the client — 401 is 401.
			apiresp.Respond(c, apperr.ErrUnauthorized, requestID)
			c.Abort()
			return
		}

		c.Set(UserIDKey, userID)
		c.Set(JTIKey, jti)
		c.Next()
	}
}

// UserIDFromContext is the type-safe reader for the user_id key.
func UserIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get(UserIDKey)
	if !ok {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}

// JTIFromContext is the type-safe reader for the jti key.
func JTIFromContext(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get(JTIKey)
	if !ok {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}
