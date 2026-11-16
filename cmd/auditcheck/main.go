package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"UserManagementSystem/internal/config"
	"UserManagementSystem/internal/database"
	"UserManagementSystem/internal/handler"
	"UserManagementSystem/internal/repository"
	"UserManagementSystem/internal/router"
	"UserManagementSystem/internal/security"
	"UserManagementSystem/internal/service"
)

const (
	adminEmail = "ac-admin@example.com"
	userEmail  = "ac-user@example.com"
	sharedPass = "correct-horse-battery-staple"
)

type env struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	client   *http.Client
	base     string
	srv      *httptest.Server
	roleRepo *repository.PGRoleRepo
	userRepo repository.UserRepository
	authSvc  *service.AuthService

	adminID, userID   string
	adminTok, userTok string
}

type auditRow struct {
	ActorUserID *uuid.UUID
	EntityType  *string
	EntityID    *uuid.UUID
	IPAddress   *string
	RequestID   *string
	Metadata    map[string]any
}

// main is a thin wrapper so that deferred cleanup in run() executes on
// every exit path, including test failures. log.Fatalf would bypass defers.
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	pool, err := database.NewPool(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer pool.Close()

	hasher := security.NewPasswordHasher(cfg.Auth.MaxConcurrentHashes)
	jwtIssuer := security.NewJWTIssuer(cfg.Auth.JWTSecret, cfg.Auth.JWTIssuer, cfg.Auth.AccessTokenTTL)
	userRepo := repository.NewPGUserRepo()
	roleRepo := repository.NewPGRoleRepo()
	permRepo := repository.NewPGPermissionRepo()
	tokenRepo := repository.NewPGRefreshTokenRepo()
	auditRepo := repository.NewPGAuditLogRepo()
	audit := service.NewRealAudit(pool, auditRepo)

	authSvc, err := service.NewAuthService(pool, userRepo, tokenRepo, roleRepo,
		hasher, jwtIssuer, audit, cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL)
	if err != nil {
		return fmt.Errorf("auth svc: %w", err)
	}
	userSvc := service.NewUserService(pool, userRepo, roleRepo, hasher, audit)
	roleSvc := service.NewRoleService(pool, roleRepo, audit)
	permSvc := service.NewPermissionService(pool, permRepo, audit)
	resolver := service.NewDBPermissionsResolver(pool, userRepo)
	verifier := security.JWTVerifierAdapter{Issuer: jwtIssuer}

	r := router.New(
		handler.NewHealthHandler(pool),
		handler.NewAuthHandler(authSvc, cfg.Auth, cfg.Cookie),
		handler.NewUserHandler(userSvc),
		handler.NewRoleHandler(roleSvc),
		handler.NewPermissionHandler(permSvc),
		verifier, resolver,
	)
	srv := httptest.NewServer(r)
	defer srv.Close()

	e := &env{
		ctx:      ctx,
		pool:     pool,
		client:   &http.Client{Timeout: 5 * time.Second},
		base:     srv.URL,
		srv:      srv,
		roleRepo: roleRepo,
		userRepo: userRepo,
		authSvc:  authSvc,
	}

	if err := cleanup(ctx, pool); err != nil {
		return fmt.Errorf("pre-run cleanup: %w", err)
	}
	defer func() {
		if cerr := cleanup(context.Background(), pool); cerr != nil {
			fmt.Fprintln(os.Stderr, "post-run cleanup failed:", cerr)
		}
	}()

	if err := setup(ctx, e); err != nil {
		return fmt.Errorf("setup: %w", err)
	}

	tests := []struct {
		name string
		fn   func(*env) error
	}{
		{"01 register writes user.registered",          testRegister},
		{"02 login success writes auth.login.success",  testLoginSuccess},
		{"03 login wrong password writes failed+actor", testLoginWrongPass},
		{"04 login unknown email writes failed+nil",    testLoginUnknown},
		{"05 refresh writes auth.refresh",              testRefresh},
		{"06 logout writes auth.logout",                testLogout},
		{"07 logout-all writes auth.logout_all",        testLogoutAll},
		{"08 admin create user writes audit (actor)",   testAdminCreateUser},
		{"09 admin create role writes audit",           testAdminCreateRole},
		{"10 admin create perm writes audit",           testAdminCreatePerm},
	}

	for _, t := range tests {
		fmt.Printf("=== %s ===\n", t.name)
		if err := t.fn(e); err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		}
	}
	fmt.Println("ALL EXERCISES PASSED")
	return nil
}

func setup(ctx context.Context, e *env) error {
	for _, r := range []struct {
		email   string
		isAdmin bool
		idPtr   *string
		tokPtr  *string
	}{
		{adminEmail, true, &e.adminID, &e.adminTok},
		{userEmail, false, &e.userID, &e.userTok},
	} {
		u, err := e.authSvc.Register(ctx, service.RegisterInput{
			Email: r.email, Password: sharedPass, FullName: r.email,
		})
		if err != nil {
			return fmt.Errorf("register %s: %w", r.email, err)
		}
		*r.idPtr = u.ID.String()
		if r.isAdmin {
			role, err := e.roleRepo.GetByName(ctx, e.pool, "admin")
			if err != nil {
				return fmt.Errorf("lookup admin role: %w", err)
			}
			if err := e.userRepo.AssignRole(ctx, e.pool, u.ID, role.ID); err != nil {
				return fmt.Errorf("assign admin role: %w", err)
			}
		}
		pair, err := e.authSvc.Login(ctx, service.LoginInput{Email: r.email, Password: sharedPass}, nil, nil)
		if err != nil {
			return fmt.Errorf("login %s: %w", r.email, err)
		}
		*r.tokPtr = pair.AccessToken
	}
	return nil
}

func cleanup(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`DELETE FROM audit_logs WHERE actor_user_id IN (SELECT id FROM users WHERE email LIKE 'ac-%')`,
		`DELETE FROM users WHERE email LIKE 'ac-%'`,
		`DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE name LIKE 'ac-%')`,
		`DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE name LIKE 'ac-%')`,
		`DELETE FROM roles WHERE name LIKE 'ac-%'`,
		`DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code LIKE 'ac.%')`,
		`DELETE FROM permissions WHERE code LIKE 'ac.%'`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("cleanup stmt %q: %w", s, err)
		}
	}
	return nil
}

func (e *env) do(method, path, body, bearer string) (int, []byte, http.Header, error) {
	var rdr io.Reader
	if body != "" {
		rdr = bytes.NewBufferString(body)
	}
	req, err := http.NewRequestWithContext(e.ctx, method, e.base+path, rdr)
	if err != nil {
		return 0, nil, nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header, err
}

// getAudit fetches exactly one row matching (request_id, action). Uses
// host(ip_address) so the string compares equal to what the production
// repository returns (INET ::text includes the /32 mask; host() strips it).
func (e *env) getAudit(reqID, action string) (*auditRow, error) {
	rows, err := e.pool.Query(e.ctx, `
		SELECT actor_user_id, entity_type, entity_id,
		       host(ip_address) AS ip_address, request_id, metadata
		FROM audit_logs
		WHERE request_id = $1 AND action = $2
	`, reqID, action)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(
			&r.ActorUserID, &r.EntityType, &r.EntityID,
			&r.IPAddress, &r.RequestID, &r.Metadata,
		); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) != 1 {
		return nil, fmt.Errorf(
			"expected exactly 1 audit row, got %d (request_id=%s action=%s)",
			len(out), reqID, action)
	}
	return out[0], nil
}

func (e *env) expectErr(method, path, body, bearer string, wantStatus int) (http.Header, error) {
	status, respBody, headers, err := e.do(method, path, body, bearer)
	if err != nil {
		return nil, err
	}
	if status != wantStatus {
		return nil, fmt.Errorf("%s %s: status=%d want=%d body=%s",
			method, path, status, wantStatus, respBody)
	}
	return headers, nil
}

func reqIDOf(h http.Header) string { return h.Get("X-Request-ID") }

func derefStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// ---------- tests ----------

func testRegister(e *env) error {
	email := "ac-register@example.com"
	status, _, headers, err := e.do("POST", "/api/v1/auth/register",
		`{"email":"`+email+`","password":"`+sharedPass+`","full_name":"Reg"}`, "")
	if err != nil {
		return err
	}
	if status != 201 {
		return fmt.Errorf("status=%d", status)
	}

	reqID := reqIDOf(headers)
	if reqID == "" {
		return fmt.Errorf("missing X-Request-ID header")
	}

	row, err := e.getAudit(reqID, "user.registered")
	if err != nil {
		return err
	}

	if row.ActorUserID == nil {
		return fmt.Errorf("actor_user_id is nil")
	}
	if row.EntityType == nil || *row.EntityType != "user" {
		return fmt.Errorf("entity_type=%q want=%q", derefStr(row.EntityType), "user")
	}
	if row.IPAddress == nil || *row.IPAddress != "127.0.0.1" {
		return fmt.Errorf("ip=%q want=%q", derefStr(row.IPAddress), "127.0.0.1")
	}
	if v, ok := row.Metadata["email"].(string); !ok || v != email {
		return fmt.Errorf("metadata.email=%v want=%q", row.Metadata["email"], email)
	}

	fmt.Printf("row: actor=%s entity=%s ip=%q md=%v\n",
		row.ActorUserID, *row.EntityType, *row.IPAddress, row.Metadata)
	return nil
}

func testLoginSuccess(e *env) error {
	status, _, headers, err := e.do("POST", "/api/v1/auth/login",
		`{"email":"`+userEmail+`","password":"`+sharedPass+`"}`, "")
	if err != nil || status != 200 {
		return fmt.Errorf("status=%d err=%v", status, err)
	}

	row, err := e.getAudit(reqIDOf(headers), "auth.login.success")
	if err != nil {
		return err
	}
	if row.ActorUserID == nil || row.ActorUserID.String() != e.userID {
		return fmt.Errorf("actor=%v want=%s", row.ActorUserID, e.userID)
	}
	if row.IPAddress == nil || *row.IPAddress != "127.0.0.1" {
		return fmt.Errorf("ip=%q want=%q", derefStr(row.IPAddress), "127.0.0.1")
	}

	fmt.Printf("row: actor=%s ip=%q\n", row.ActorUserID, *row.IPAddress)
	return nil
}

func testLoginWrongPass(e *env) error {
	status, _, headers, err := e.do("POST", "/api/v1/auth/login",
		`{"email":"`+userEmail+`","password":"wrong-password-xxxx"}`, "")
	if err != nil || status != 401 {
		return fmt.Errorf("status=%d", status)
	}

	row, err := e.getAudit(reqIDOf(headers), "auth.login.failed")
	if err != nil {
		return err
	}
	if row.ActorUserID == nil || row.ActorUserID.String() != e.userID {
		return fmt.Errorf("actor=%v want=%s", row.ActorUserID, e.userID)
	}
	if v, ok := row.Metadata["reason"].(string); !ok || v != "bad_password" {
		return fmt.Errorf("reason=%v want=bad_password", row.Metadata["reason"])
	}

	fmt.Printf("row: actor=%s reason=bad_password\n", row.ActorUserID)
	return nil
}

func testLoginUnknown(e *env) error {
	status, _, headers, err := e.do("POST", "/api/v1/auth/login",
		`{"email":"ac-unknown-xyz@example.com","password":"whatever-12345"}`, "")
	if err != nil || status != 401 {
		return fmt.Errorf("status=%d", status)
	}

	row, err := e.getAudit(reqIDOf(headers), "auth.login.failed")
	if err != nil {
		return err
	}
	if row.ActorUserID != nil {
		return fmt.Errorf("actor=%v, expected nil (unknown email)", row.ActorUserID)
	}
	if v, ok := row.Metadata["reason"].(string); !ok || v != "unknown_email" {
		return fmt.Errorf("reason=%v want=unknown_email", row.Metadata["reason"])
	}

	fmt.Println("row: actor=nil reason=unknown_email")
	return nil
}

func testRefresh(e *env) error {
	status, body, _, err := e.do("POST", "/api/v1/auth/login",
		`{"email":"`+userEmail+`","password":"`+sharedPass+`"}`, "")
	if err != nil || status != 200 {
		return fmt.Errorf("login: status=%d err=%v", status, err)
	}
	var lr struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &lr); err != nil {
		return fmt.Errorf("unmarshal login response: %w", err)
	}

	status, _, headers, err := e.do("POST", "/api/v1/auth/refresh",
		`{"refresh_token":"`+lr.RefreshToken+`"}`, "")
	if err != nil || status != 200 {
		return fmt.Errorf("refresh: status=%d err=%v", status, err)
	}

	row, err := e.getAudit(reqIDOf(headers), "auth.refresh")
	if err != nil {
		return err
	}
	if row.ActorUserID == nil || row.ActorUserID.String() != e.userID {
		return fmt.Errorf("actor=%v want=%s", row.ActorUserID, e.userID)
	}

	fmt.Printf("row: actor=%s\n", row.ActorUserID)
	return nil
}

func testLogout(e *env) error {
	status, body, _, err := e.do("POST", "/api/v1/auth/login",
		`{"email":"`+userEmail+`","password":"`+sharedPass+`"}`, "")
	if err != nil || status != 200 {
		return fmt.Errorf("login: status=%d err=%v", status, err)
	}
	var lr struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &lr); err != nil {
		return fmt.Errorf("unmarshal login response: %w", err)
	}

	status, _, headers, err := e.do("POST", "/api/v1/auth/logout",
		`{"refresh_token":"`+lr.RefreshToken+`"}`, "")
	if err != nil || status != 204 {
		return fmt.Errorf("logout: status=%d err=%v", status, err)
	}

	row, err := e.getAudit(reqIDOf(headers), "auth.logout")
	if err != nil {
		return err
	}
	if row.ActorUserID == nil || row.ActorUserID.String() != e.userID {
		return fmt.Errorf("actor=%v want=%s", row.ActorUserID, e.userID)
	}

	fmt.Printf("row: actor=%s\n", row.ActorUserID)
	return nil
}

func testLogoutAll(e *env) error {
	headers, err := e.expectErr("POST", "/api/v1/auth/logout-all", "", e.userTok, 204)
	if err != nil {
		return err
	}

	row, err := e.getAudit(reqIDOf(headers), "auth.logout_all")
	if err != nil {
		return err
	}
	if row.ActorUserID == nil || row.ActorUserID.String() != e.userID {
		return fmt.Errorf("actor=%v want=%s", row.ActorUserID, e.userID)
	}

	fmt.Printf("row: actor=%s\n", row.ActorUserID)
	return nil
}

func testAdminCreateUser(e *env) error {
	email := "ac-target@example.com"
	status, _, headers, err := e.do("POST", "/api/v1/users",
		`{"email":"`+email+`","password":"`+sharedPass+`","full_name":"Target"}`, e.adminTok)
	if err != nil || status != 201 {
		return fmt.Errorf("status=%d err=%v", status, err)
	}

	row, err := e.getAudit(reqIDOf(headers), "user.created_by_admin")
	if err != nil {
		return err
	}
	if row.ActorUserID == nil || row.ActorUserID.String() != e.adminID {
		return fmt.Errorf("actor=%v want=%s", row.ActorUserID, e.adminID)
	}
	if row.EntityType == nil || *row.EntityType != "user" {
		return fmt.Errorf("entity_type=%q want=%q", derefStr(row.EntityType), "user")
	}
	if v, ok := row.Metadata["email"].(string); !ok || v != email {
		return fmt.Errorf("metadata.email=%v want=%q", row.Metadata["email"], email)
	}

	fmt.Printf("row: actor=%s (admin) entity=user target=%s\n", row.ActorUserID, email)
	return nil
}

func testAdminCreateRole(e *env) error {
	status, _, headers, err := e.do("POST", "/api/v1/roles",
		`{"name":"ac-test-role"}`, e.adminTok)
	if err != nil || status != 201 {
		return fmt.Errorf("status=%d err=%v", status, err)
	}

	row, err := e.getAudit(reqIDOf(headers), "role.created")
	if err != nil {
		return err
	}
	if row.ActorUserID == nil || row.ActorUserID.String() != e.adminID {
		return fmt.Errorf("actor=%v want=%s", row.ActorUserID, e.adminID)
	}
	if row.EntityType == nil || *row.EntityType != "role" {
		return fmt.Errorf("entity_type=%q want=%q", derefStr(row.EntityType), "role")
	}

	fmt.Printf("row: actor=%s entity=role\n", row.ActorUserID)
	return nil
}

func testAdminCreatePerm(e *env) error {
	status, _, headers, err := e.do("POST", "/api/v1/permissions",
		`{"code":"ac.test.perm"}`, e.adminTok)
	if err != nil || status != 201 {
		return fmt.Errorf("status=%d err=%v", status, err)
	}

	row, err := e.getAudit(reqIDOf(headers), "permission.created")
	if err != nil {
		return err
	}
	if row.ActorUserID == nil || row.ActorUserID.String() != e.adminID {
		return fmt.Errorf("actor=%v want=%s", row.ActorUserID, e.adminID)
	}
	if v, ok := row.Metadata["code"].(string); !ok || v != "ac.test.perm" {
		return fmt.Errorf("metadata.code=%v want=%q", row.Metadata["code"], "ac.test.perm")
	}

	fmt.Printf("row: actor=%s entity=permission md=%v\n", row.ActorUserID, row.Metadata)
	return nil
}
