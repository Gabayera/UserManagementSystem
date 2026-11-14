package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"UserManagementSystem/internal/config"
	"UserManagementSystem/internal/database"
	"UserManagementSystem/internal/dto"
	"UserManagementSystem/internal/handler"
	"UserManagementSystem/internal/repository"
	"UserManagementSystem/internal/router"
	"UserManagementSystem/internal/security"
	"UserManagementSystem/internal/service"
)

const (
	testEmail    = "httpcheck@example.com"
	testPassword = "correct-horse-battery-staple"
	cookieName   = "refresh_token"
)

type testEnv struct {
	ctx                context.Context
	pool               *pgxpool.Pool
	client             *http.Client
	base               string
	server             *httptest.Server
	refreshToken       string // live
	previousRefreshTok string // pre-rotation, for reuse test
	accessToken        string
}

func main() {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	pool, err := database.NewPool(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()

	hasher := security.NewPasswordHasher(cfg.Auth.MaxConcurrentHashes)
	jwtIssuer := security.NewJWTIssuer(cfg.Auth.JWTSecret, cfg.Auth.JWTIssuer, cfg.Auth.AccessTokenTTL)
	auditSvc := service.NewNoopAudit()

	authSvc, err := service.NewAuthService(
		pool,
		repository.NewPGUserRepo(),
		repository.NewPGRefreshTokenRepo(),
		repository.NewPGRoleRepo(),
		hasher, jwtIssuer, auditSvc,
		cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL,
	)
	if err != nil {
		log.Fatalf("auth svc: %v", err)
	}

	r := router.New(
		handler.NewHealthHandler(pool),
		handler.NewAuthHandler(authSvc, cfg.Auth, cfg.Cookie),
		security.JWTVerifierAdapter{Issuer: jwtIssuer},
	)
	srv := httptest.NewServer(r)
	defer srv.Close()

	env := &testEnv{
		ctx:    ctx,
		pool:   pool,
		client: &http.Client{Timeout: 5 * time.Second},
		base:   srv.URL,
		server: srv,
	}

	if err := cleanup(ctx, pool); err != nil {
		log.Fatalf("cleanup: %v", err)
	}
	defer func() { _ = cleanup(context.Background(), pool) }()

	tests := []struct {
		name string
		fn   func(*testEnv) error
	}{
		{"01 register happy", test01},
		{"02 register duplicate", test02},
		{"03 register invalid email", test03},
		{"04 register short password", test04},
		{"05 login correct", test05},
		{"06 login wrong password", test06},
		{"07 me with bearer", test07},
		{"08 me no auth", test08},
		{"09 me garbage bearer", test09},
		{"10 me basic auth scheme", test10},
		{"11 refresh rotates", test11},
		{"12 refresh revoked cookie", test12},
		{"13 logout", test13},
		{"14 refresh after logout", test14},
		{"15 logout-all", test15},
		{"16 refresh after logout-all", test16},
		{"17 logout-all no auth", test17},
	}

	for _, t := range tests {
		fmt.Printf("=== %s ===\n", t.name)
		if err := t.fn(env); err != nil {
			log.Fatalf("%s: %v", t.name, err)
		}
	}
	fmt.Println("ALL EXERCISES PASSED")
}

// ---------- helpers ----------

func (e *testEnv) do(method, path string, body any, bearer, cookieVal string) (*http.Response, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(e.ctx, method, e.base+path, rdr)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookieVal != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieVal})
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, data, nil
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func parseError(body []byte) (dto.ErrorEnvelope, error) {
	var e dto.ErrorEnvelope
	err := json.Unmarshal(body, &e)
	return e, err
}

func expectStatus(resp *http.Response, body []byte, want int) error {
	if resp.StatusCode != want {
		return fmt.Errorf("status=%d want=%d body=%s", resp.StatusCode, want, body)
	}
	return nil
}

func expectErrCode(resp *http.Response, body []byte, wantStatus int, wantCode string) error {
	if err := expectStatus(resp, body, wantStatus); err != nil {
		return err
	}
	env, err := parseError(body)
	if err != nil {
		return fmt.Errorf("unmarshal error envelope: %w (body=%s)", err, body)
	}
	if env.Error.Code != wantCode {
		return fmt.Errorf("code=%q want=%q body=%s", env.Error.Code, wantCode, body)
	}
	return nil
}

func cleanup(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx,
		`DELETE FROM audit_logs WHERE actor_user_id = (SELECT id FROM users WHERE email = $1)`,
		testEmail); err != nil {
		return err
	}
	_, err := pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, testEmail)
	return err
}

// ---------- test cases ----------

func test01(e *testEnv) error {
	start := time.Now()
	resp, body, err := e.do("POST", "/api/v1/auth/register", map[string]string{
		"email": testEmail, "password": testPassword, "full_name": "HTTP Check",
	}, "", "")
	if err != nil {
		return err
	}
	elapsed := time.Since(start)
	if err := expectStatus(resp, body, 201); err != nil {
		return err
	}
	var parsed dto.RegisterResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("unmarshal: %w body=%s", err, body)
	}
	if parsed.ID == "" || parsed.Email != testEmail || parsed.FullName != "HTTP Check" {
		return fmt.Errorf("unexpected body: %s", body)
	}
	if strings.Contains(string(body), "password") {
		return fmt.Errorf("register response leaks password: %s", body)
	}
	if elapsed < 10*time.Millisecond {
		return fmt.Errorf("register suspiciously fast (%v) — Argon2id should take ~40ms", elapsed)
	}
	fmt.Printf("registered id=%s elapsed=%v\n", parsed.ID, elapsed.Round(time.Millisecond))
	return nil
}

func test02(e *testEnv) error {
	resp, body, err := e.do("POST", "/api/v1/auth/register", map[string]string{
		"email": testEmail, "password": testPassword, "full_name": "Dup",
	}, "", "")
	if err != nil {
		return err
	}
	if err := expectErrCode(resp, body, 409, dto.CodeConflict); err != nil {
		return err
	}
	fmt.Println("duplicate email: 409 conflict")
	return nil
}

func test03(e *testEnv) error {
	resp, body, err := e.do("POST", "/api/v1/auth/register", map[string]string{
		"email": "not-an-email", "password": testPassword, "full_name": "X",
	}, "", "")
	if err != nil {
		return err
	}
	if err := expectErrCode(resp, body, 422, dto.CodeInvalidInput); err != nil {
		return err
	}
	fmt.Println("invalid email: 422 invalid_input")
	return nil
}

func test04(e *testEnv) error {
	resp, body, err := e.do("POST", "/api/v1/auth/register", map[string]string{
		"email": "short@example.com", "password": "short", "full_name": "X",
	}, "", "")
	if err != nil {
		return err
	}
	if err := expectErrCode(resp, body, 422, dto.CodeInvalidInput); err != nil {
		return err
	}
	fmt.Println("short password: 422 invalid_input")
	return nil
}

func test05(e *testEnv) error {
	start := time.Now()
	resp, body, err := e.do("POST", "/api/v1/auth/login", map[string]string{
		"email": testEmail, "password": testPassword,
	}, "", "")
	if err != nil {
		return err
	}
	elapsed := time.Since(start)
	if err := expectStatus(resp, body, 200); err != nil {
		return err
	}
	if elapsed < 5*time.Millisecond {
		return fmt.Errorf("login suspiciously fast (%v)", elapsed)
	}
	var parsed dto.LoginResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	if parsed.AccessToken == "" || parsed.TokenType != "Bearer" || parsed.ExpiresIn <= 0 {
		return fmt.Errorf("bad body: %s", body)
	}
	if parsed.RefreshToken == "" {
		return fmt.Errorf("body missing refresh_token")
	}
	c := findCookie(resp, cookieName)
	if c == nil || c.Value == "" {
		return fmt.Errorf("missing Set-Cookie: %s", body)
	}
	if !c.HttpOnly {
		return fmt.Errorf("cookie not HttpOnly")
	}
	if c.SameSite != http.SameSiteStrictMode {
		return fmt.Errorf("cookie SameSite not Strict (got %v)", c.SameSite)
	}
	if c.Path != "/api/v1/auth" {
		return fmt.Errorf("cookie Path=%q", c.Path)
	}
	if c.MaxAge <= 0 {
		return fmt.Errorf("cookie MaxAge=%d", c.MaxAge)
	}
	e.accessToken = parsed.AccessToken
	e.refreshToken = parsed.RefreshToken
	fmt.Printf("login ok expires_in=%d elapsed=%v cookie_httponly=%v\n",
		parsed.ExpiresIn, elapsed.Round(time.Millisecond), c.HttpOnly)
	return nil
}

func test06(e *testEnv) error {
	start := time.Now()
	resp, body, err := e.do("POST", "/api/v1/auth/login", map[string]string{
		"email": testEmail, "password": "wrong-password-123",
	}, "", "")
	if err != nil {
		return err
	}
	elapsed := time.Since(start)
	if err := expectErrCode(resp, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	if c := findCookie(resp, cookieName); c != nil {
		return fmt.Errorf("failed login must not set cookie: %+v", c)
	}
	if elapsed < 5*time.Millisecond {
		return fmt.Errorf("wrong-password login suspiciously fast (%v)", elapsed)
	}
	fmt.Printf("wrong password: 401 elapsed=%v\n", elapsed.Round(time.Millisecond))
	return nil
}

func test07(e *testEnv) error {
	resp, body, err := e.do("GET", "/api/v1/auth/me", nil, e.accessToken, "")
	if err != nil {
		return err
	}
	if err := expectStatus(resp, body, 200); err != nil {
		return err
	}
	var parsed dto.MeResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("unmarshal: %w body=%s", err, body)
	}
	if parsed.User.ID == "" || parsed.User.Email != testEmail {
		return fmt.Errorf("bad user: %+v", parsed.User)
	}
	if strings.Contains(string(body), "password") {
		return fmt.Errorf("me response leaks password: %s", body)
	}
	hasUserRole := false
	for _, r := range parsed.Roles {
		if r.Name == "user" {
			hasUserRole = true
		}
	}
	if !hasUserRole {
		return fmt.Errorf("missing 'user' role: %+v", parsed.Roles)
	}
	hasReadPerm := false
	for _, p := range parsed.Permissions {
		if p.Code == "user.read" {
			hasReadPerm = true
		}
	}
	if !hasReadPerm {
		return fmt.Errorf("missing 'user.read' permission: %+v", parsed.Permissions)
	}
	fmt.Printf("me: user=%s roles=%d perms=%d\n", parsed.User.ID, len(parsed.Roles), len(parsed.Permissions))
	return nil
}

func test08(e *testEnv) error {
	resp, body, err := e.do("GET", "/api/v1/auth/me", nil, "", "")
	if err != nil {
		return err
	}
	if err := expectErrCode(resp, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	fmt.Println("me without auth: 401")
	return nil
}

func test09(e *testEnv) error {
	resp, body, err := e.do("GET", "/api/v1/auth/me", nil, "garbage-not-a-jwt", "")
	if err != nil {
		return err
	}
	if err := expectErrCode(resp, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	fmt.Println("me with garbage bearer: 401")
	return nil
}

func test10(e *testEnv) error {
	req, err := http.NewRequestWithContext(e.ctx, "GET", e.base+"/api/v1/auth/me", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if err := expectErrCode(resp, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	fmt.Println("me with Basic auth: 401")
	return nil
}

func test11(e *testEnv) error {
	oldRaw := e.refreshToken
	resp, body, err := e.do("POST", "/api/v1/auth/refresh", nil, "", oldRaw)
	if err != nil {
		return err
	}
	if err := expectStatus(resp, body, 200); err != nil {
		return err
	}
	var parsed dto.RefreshResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("unmarshal: %w body=%s", err, body)
	}
	if parsed.AccessToken == "" {
		return fmt.Errorf("no access_token")
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return err
	}
	if _, ok := raw["refresh_token"]; ok {
		return fmt.Errorf("refresh response must NOT include refresh_token in body: %s", body)
	}
	c := findCookie(resp, cookieName)
	if c == nil || c.Value == "" {
		return fmt.Errorf("refresh must set new cookie")
	}
	if c.Value == oldRaw {
		return fmt.Errorf("refresh token not rotated")
	}
	e.accessToken = parsed.AccessToken
	e.previousRefreshTok = oldRaw
	e.refreshToken = c.Value
	fmt.Printf("refresh rotated old_len=%d new_len=%d\n", len(oldRaw), len(c.Value))
	return nil
}

func test12(e *testEnv) error {
	resp, body, err := e.do("POST", "/api/v1/auth/refresh", nil, "", e.previousRefreshTok)
	if err != nil {
		return err
	}
	if err := expectErrCode(resp, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	c := findCookie(resp, cookieName)
	if c == nil {
		return fmt.Errorf("expected Set-Cookie clearing the refresh token")
	}
	if c.Value != "" || c.MaxAge > 0 {
		return fmt.Errorf("cookie not cleared: value=%q maxage=%d", c.Value, c.MaxAge)
	}
	fmt.Println("reuse detected: 401, cookie cleared")
	return nil
}

func test13(e *testEnv) error {
	// Fresh login to get a valid cookie (the previous family is fully revoked).
	loginResp, loginBody, err := e.do("POST", "/api/v1/auth/login", map[string]string{
		"email": testEmail, "password": testPassword,
	}, "", "")
	if err != nil {
		return err
	}
	if err := expectStatus(loginResp, loginBody, 200); err != nil {
		return err
	}
	var loginParsed dto.LoginResponse
	if err := json.Unmarshal(loginBody, &loginParsed); err != nil {
		return err
	}
	loginCookie := findCookie(loginResp, cookieName)
	if loginCookie == nil || loginCookie.Value == "" {
		return fmt.Errorf("no cookie on login")
	}

	resp, body, err := e.do("POST", "/api/v1/auth/logout", nil, "", loginCookie.Value)
	if err != nil {
		return err
	}
	if resp.StatusCode != 204 {
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, body)
	}
	c := findCookie(resp, cookieName)
	if c == nil || c.Value != "" {
		return fmt.Errorf("logout must clear cookie: %+v", c)
	}
	e.refreshToken = loginCookie.Value
	fmt.Println("logout: 204, cookie cleared")
	return nil
}

func test14(e *testEnv) error {
	resp, body, err := e.do("POST", "/api/v1/auth/refresh", nil, "", e.refreshToken)
	if err != nil {
		return err
	}
	if err := expectErrCode(resp, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	fmt.Println("refresh after logout: 401")
	return nil
}

func test15(e *testEnv) error {
	loginResp, loginBody, err := e.do("POST", "/api/v1/auth/login", map[string]string{
		"email": testEmail, "password": testPassword,
	}, "", "")
	if err != nil {
		return err
	}
	if err := expectStatus(loginResp, loginBody, 200); err != nil {
		return err
	}
	var parsed dto.LoginResponse
	if err := json.Unmarshal(loginBody, &parsed); err != nil {
		return err
	}
	loginCookie := findCookie(loginResp, cookieName)
	if loginCookie == nil {
		return fmt.Errorf("no cookie")
	}

	resp, body, err := e.do("POST", "/api/v1/auth/logout-all", nil, parsed.AccessToken, "")
	if err != nil {
		return err
	}
	if resp.StatusCode != 204 {
		return fmt.Errorf("status=%d body=%s", resp.StatusCode, body)
	}
	c := findCookie(resp, cookieName)
	if c == nil || c.Value != "" {
		return fmt.Errorf("logout-all must clear cookie")
	}
	e.refreshToken = loginCookie.Value
	fmt.Println("logout-all: 204, cookie cleared")
	return nil
}

func test16(e *testEnv) error {
	resp, body, err := e.do("POST", "/api/v1/auth/refresh", nil, "", e.refreshToken)
	if err != nil {
		return err
	}
	if err := expectErrCode(resp, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	fmt.Println("refresh after logout-all: 401")
	return nil
}

func test17(e *testEnv) error {
	resp, body, err := e.do("POST", "/api/v1/auth/logout-all", nil, "", "")
	if err != nil {
		return err
	}
	if err := expectErrCode(resp, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	fmt.Println("logout-all without auth: 401")
	return nil
}
