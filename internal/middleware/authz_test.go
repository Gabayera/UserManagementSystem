package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"UserManagementSystem/internal/dto"
	"UserManagementSystem/internal/service"
)

type fakeResolver struct {
	fn func(ctx context.Context, userID uuid.UUID) (map[string]struct{}, error)
}

func (f *fakeResolver) PermissionsForUser(ctx context.Context, userID uuid.UUID) (map[string]struct{}, error) {
	if f.fn == nil {
		return nil, errors.New("not configured")
	}
	return f.fn(ctx, userID)
}

var _ service.PermissionsResolver = (*fakeResolver)(nil)

// newAuthzRouter wires Auth-then-RequirePermission with the given resolver.
// authenticated=false means Auth is NOT chained (simulates middleware-order bug).
func newAuthzRouter(r service.PermissionsResolver, code string, authenticated bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	rtr := gin.New()
	rtr.Use(RequestID())
	rtr.Use(RequestContext())
	if authenticated {
		uid := uuid.MustParse("11111111-1111-1111-1111-111111111111")
		rtr.Use(func(c *gin.Context) {
			c.Set(UserIDKey, uid)
			SetAuthenticatedUser(c, uid)
			c.Next()
		})
	}
	rtr.Use(RequirePermission(r, code))
	rtr.GET("/x", func(c *gin.Context) { c.Status(200) })
	return rtr
}

func TestRequirePermission_NoUserInContext_Returns500(t *testing.T) {
	r := newAuthzRouter(&fakeResolver{fn: func(ctx context.Context, uid uuid.UUID) (map[string]struct{}, error) {
		t.Fatal("resolver should not be called when user_id missing")
		return nil, nil
	}}, "user.read", false)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))

	if w.Code != 500 {
		t.Fatalf("status=%d want 500 (middleware-order bug)", w.Code)
	}
}

func TestRequirePermission_ResolverError_FailsClosed(t *testing.T) {
	r := newAuthzRouter(&fakeResolver{fn: func(ctx context.Context, uid uuid.UUID) (map[string]struct{}, error) {
		return nil, errors.New("simulated resolver outage")
	}}, "user.read", true)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))

	// Critical security property: resolver outage must NOT become a bypass.
	if w.Code == 200 {
		t.Fatal("FAIL-CLOSED VIOLATED: resolver error returned 200")
	}
	if w.Code < 500 || w.Code >= 600 {
		t.Fatalf("status=%d want 5xx", w.Code)
	}
}

func TestRequirePermission_EmptyPermissions_Returns403(t *testing.T) {
	r := newAuthzRouter(&fakeResolver{fn: func(ctx context.Context, uid uuid.UUID) (map[string]struct{}, error) {
		return map[string]struct{}{}, nil
	}}, "user.read", true)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))

	if w.Code != 403 {
		t.Fatalf("status=%d want 403 (default deny)", w.Code)
	}
	var env dto.ErrorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Error.Code != dto.CodeForbidden {
		t.Fatalf("code=%q", env.Error.Code)
	}
}

func TestRequirePermission_HasPermission_Returns200(t *testing.T) {
	r := newAuthzRouter(&fakeResolver{fn: func(ctx context.Context, uid uuid.UUID) (map[string]struct{}, error) {
		return map[string]struct{}{"user.read": {}}, nil
	}}, "user.read", true)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))

	if w.Code != 200 {
		t.Fatalf("status=%d want 200 body=%s", w.Code, w.Body.String())
	}
}

func TestRequirePermission_UnknownCode_Returns403(t *testing.T) {
	r := newAuthzRouter(&fakeResolver{fn: func(ctx context.Context, uid uuid.UUID) (map[string]struct{}, error) {
		return map[string]struct{}{"user.read": {}}, nil
	}}, "nonexistent.code", true)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))

	if w.Code != 403 {
		t.Fatalf("status=%d want 403", w.Code)
	}
}
