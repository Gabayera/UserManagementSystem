package service

import (
	"context"

	"github.com/google/uuid"
)

// RequestContext carries request-scoped metadata that cross-cuts middleware
// and services: request ID, client IP, and authenticated user ID. Stored in
// the standard context.Context by middleware.RequestContext() so that
// service-layer code (RealAudit) can read it without importing gin.
//
// Lives in the `service` package (not `middleware`) to avoid an import cycle:
// middleware already imports service for PermissionsResolver; service must
// not import middleware.
type RequestContext struct {
	RequestID string
	IPAddress string
	UserID    *uuid.UUID // nil when unauthenticated
}

type reqCtxKey struct{}

// WithRequestContext returns a new context.Context carrying rc. Callers
// replace the whole value when fields change (e.g., SetAuthenticatedUser
// adds UserID). Context values are immutable — never mutate in place.
func WithRequestContext(ctx context.Context, rc RequestContext) context.Context {
	return context.WithValue(ctx, reqCtxKey{}, rc)
}

// RequestContextFromContext returns the request context or (zero, false) if
// none was set. Callers must handle the false case gracefully — RealAudit
// falls back to zero values, which produce NULL columns in audit_logs.
func RequestContextFromContext(ctx context.Context) (RequestContext, bool) {
	rc, ok := ctx.Value(reqCtxKey{}).(RequestContext)
	return rc, ok
}
