package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/config"
	"UserManagementSystem/internal/domain"
	"UserManagementSystem/internal/dto"
	"UserManagementSystem/internal/middleware"
	"UserManagementSystem/internal/service"
)

type fakeAuthService struct {
	RegisterFn  func(ctx context.Context, in service.RegisterInput) (*domain.User, error)
	LoginFn     func(ctx context.Context, in service.LoginInput, ua, ip *string) (*service.TokenPair, error)
	RefreshFn   func(ctx context.Context, raw string, ua, ip *string) (*service.TokenPair, error)
	LogoutFn    func(ctx context.Context, raw string) error
	LogoutAllFn func(ctx context.Context, userID uuid.UUID) error
	MeFn        func(ctx context.Context, userID uuid.UUID) (*service.MeOutput, error)
}

func (f *fakeAuthService) Register(ctx context.Context, in service.RegisterInput) (*domain.User, error) {
	return f.RegisterFn(ctx, in)
}
func (f *fakeAuthService) Login(ctx context.Context, in service.LoginInput, ua, ip *string) (*service.TokenPair, error) {
	return f.LoginFn(ctx, in, ua, ip)
}
func (f *fakeAuthService) Refresh(ctx context.Context, raw string, ua, ip *string) (*service.TokenPair, error) {
	return f.RefreshFn(ctx, raw, ua, ip)
}
func (f *fakeAuthService) Logout(ctx context.Context, raw string) error { return f.LogoutFn(ctx, raw) }
func (f *fakeAuthService) LogoutAll(ctx context.Context, uid uuid.UUID) error {
	return f.LogoutAllFn(ctx, uid)
}
func (f *fakeAuthService) Me(ctx context.Context, uid uuid.UUID) (*service.MeOutput, error) {
	return f.MeFn(ctx, uid)
}

var _ authService = (*fakeAuthService)(nil)

func newAuthHandlerRouter(svc authService, userID *uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(middleware.RequestIDKey, "test-req")
		if userID != nil {
			c.Set(middleware.UserIDKey, *userID)
		}
		c.Next()
	})
	authCfg := config.AuthConfig{
		JWTSecret:       []byte("test-secret-at-least-32-bytes-long-xxxxxx"),
		JWTIssuer:       "test",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
	}
	cookieCfg := config.CookieConfig{
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		Path:     "/api/v1/auth",
	}
	h := NewAuthHandler(svc, authCfg, cookieCfg)
	r.POST("/register", h.Register)
	r.POST("/login", h.Login)
	r.POST("/refresh", h.Refresh)
	r.POST("/logout", h.Logout)
	r.POST("/logout-all", h.LogoutAll)
	r.GET("/me", h.Me)
	return r
}

func doReq(r http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAuthHandler_Register_201_NoPasswordLeak(t *testing.T) {
	svc := &fakeAuthService{
		RegisterFn: func(ctx context.Context, in service.RegisterInput) (*domain.User, error) {
			return &domain.User{
				ID:        uuid.New(),
				Email:     in.Email,
				FullName:  in.FullName,
				IsActive:  true,
				CreatedAt: time.Now().UTC(),
			}, nil
		},
	}
	r := newAuthHandlerRouter(svc, nil)
	w := doReq(r, "POST", "/register", `{"email":"x@y.com","password":"password123","full_name":"X"}`)

	if w.Code != 201 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, banned := range []string{"password", "password_hash", "hash"} {
		if strings.Contains(body, banned) {
			t.Fatalf("body leaks %q: %s", banned, body)
		}
	}
}

func TestAuthHandler_Register_422_InvalidInput(t *testing.T) {
	svc := &fakeAuthService{}
	r := newAuthHandlerRouter(svc, nil)
	w := doReq(r, "POST", "/register", `{"email":"not-an-email"}`)

	if w.Code != 422 {
		t.Fatalf("status=%d want 422", w.Code)
	}
	var env dto.ErrorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Error.Code != dto.CodeInvalidInput {
		t.Fatalf("code=%q", env.Error.Code)
	}
}

func TestAuthHandler_Login_Success_SetsCookie(t *testing.T) {
	svc := &fakeAuthService{
		LoginFn: func(ctx context.Context, in service.LoginInput, ua, ip *string) (*service.TokenPair, error) {
			return &service.TokenPair{
				AccessToken:  "access-token",
				RefreshToken: "refresh-token-abcdefghij",
				ExpiresIn:    900,
			}, nil
		},
	}
	r := newAuthHandlerRouter(svc, nil)
	w := doReq(r, "POST", "/login", `{"email":"x@y.com","password":"password123"}`)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == "refresh_token" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("missing refresh_token cookie")
	}
	if !found.HttpOnly {
		t.Fatal("cookie must be HttpOnly")
	}
	if found.SameSite != http.SameSiteStrictMode {
		t.Fatalf("SameSite=%v", found.SameSite)
	}
	if found.Path != "/api/v1/auth" {
		t.Fatalf("Path=%q", found.Path)
	}
}

// Part 8 acceptance criterion: a failed login must NEVER set the cookie.
func TestAuthHandler_Login_WrongPassword_NoCookie(t *testing.T) {
	svc := &fakeAuthService{
		LoginFn: func(ctx context.Context, in service.LoginInput, ua, ip *string) (*service.TokenPair, error) {
			return nil, apperr.ErrUnauthorized
		},
	}
	r := newAuthHandlerRouter(svc, nil)
	w := doReq(r, "POST", "/login", `{"email":"x@y.com","password":"wrong-password"}`)

	if w.Code != 401 {
		t.Fatalf("status=%d want 401", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatalf("failed login must not set cookie, got %v", w.Result().Cookies())
	}
	var env dto.ErrorEnvelope
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	if env.Error.Code != dto.CodeUnauthorized {
		t.Fatalf("code=%q", env.Error.Code)
	}
}

func TestAuthHandler_Login_Inactive_Returns403_NoCookie(t *testing.T) {
	svc := &fakeAuthService{
		LoginFn: func(ctx context.Context, in service.LoginInput, ua, ip *string) (*service.TokenPair, error) {
			return nil, apperr.ErrForbidden
		},
	}
	r := newAuthHandlerRouter(svc, nil)
	w := doReq(r, "POST", "/login", `{"email":"x@y.com","password":"password123"}`)

	if w.Code != 403 {
		t.Fatalf("status=%d want 403", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("403 must not set cookie")
	}
}

func TestAuthHandler_Logout_204_ClearsCookie(t *testing.T) {
	svc := &fakeAuthService{
		LogoutFn: func(ctx context.Context, raw string) error { return nil },
	}
	r := newAuthHandlerRouter(svc, nil)
	w := doReq(r, "POST", "/logout", "")

	if w.Code != 204 {
		t.Fatalf("status=%d want 204", w.Code)
	}
	// Must set cookie to empty/negative MaxAge to clear it.
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "refresh_token" && (c.Value == "" || c.MaxAge < 0) {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout must clear the refresh cookie")
	}
}

func TestAuthHandler_Me_NoUserID_Returns401(t *testing.T) {
	// No userID set on context — simulates Auth middleware not chained.
	svc := &fakeAuthService{}
	r := newAuthHandlerRouter(svc, nil)
	w := doReq(r, "GET", "/me", "")

	if w.Code != 401 {
		t.Fatalf("status=%d want 401", w.Code)
	}
}

func TestAuthHandler_Me_ReturnsRolesAndPermissions(t *testing.T) {
	uid := uuid.New()
	svc := &fakeAuthService{
		MeFn: func(ctx context.Context, id uuid.UUID) (*service.MeOutput, error) {
			if id != uid {
				t.Fatalf("wrong user id")
			}
			return &service.MeOutput{
				User: &domain.User{
					ID:        uid,
					Email:     "x@y.com",
					FullName:  "X",
					IsActive:  true,
					CreatedAt: time.Now().UTC(),
					UpdatedAt: time.Now().UTC(),
				},
				Roles:       []*domain.Role{{ID: uuid.New(), Name: "user"}},
				Permissions: []*domain.Permission{{ID: uuid.New(), Code: "user.read"}},
			}, nil
		},
	}
	r := newAuthHandlerRouter(svc, &uid)
	w := doReq(r, "GET", "/me", "")

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var me dto.MeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(me.Roles) != 1 || me.Roles[0].Name != "user" {
		t.Fatalf("roles=%+v", me.Roles)
	}
	if len(me.Permissions) != 1 || me.Permissions[0].Code != "user.read" {
		t.Fatalf("permissions=%+v", me.Permissions)
	}
}

func TestAuthHandler_Refresh_ServiceError_ClearsCookie(t *testing.T) {
	svc := &fakeAuthService{
		RefreshFn: func(ctx context.Context, raw string, ua, ip *string) (*service.TokenPair, error) {
			return nil, apperr.ErrUnauthorized
		},
	}
	r := newAuthHandlerRouter(svc, nil)
	w := doReq(r, "POST", "/refresh", `{"refresh_token":"bad"}`)

	if w.Code != 401 {
		t.Fatalf("status=%d want 401", w.Code)
	}
	// Cookie must be cleared even on refresh failure.
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "refresh_token" && (c.Value == "" || c.MaxAge < 0) {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("failed refresh must clear the cookie")
	}
}

// ensure imports used
var _ = bytes.NewReader
var _ = errors.New
