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
	adminEmail  = "hc2-admin@example.com"
	editorEmail = "hc2-editor@example.com"
	userEmail   = "hc2-user@example.com"
	sharedPass  = "correct-horse-battery-staple"
)

type env struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	client   *http.Client
	base     string
	srv      *httptest.Server
	roleRepo *repository.PGRoleRepo
	userRepo repository.UserRepository

	adminTok, editorTok, userTok          string
	adminID, editorID, userID             string
	adminRoleID, editorRoleID, userRoleID string
}

type routeSpec struct {
	method, path string
	editorForbid bool
	userForbid   bool
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
	userRepo := repository.NewPGUserRepo()
	roleRepo := repository.NewPGRoleRepo()
	permRepo := repository.NewPGPermissionRepo()
	tokenRepo := repository.NewPGRefreshTokenRepo()
	auditRepo := repository.NewPGAuditLogRepo()
	audit := service.NewRealAudit(pool, auditRepo)

	authSvc, err := service.NewAuthService(pool, userRepo, tokenRepo, roleRepo, hasher, jwtIssuer, audit,
		cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL)
	if err != nil {
		log.Fatalf("auth svc: %v", err)
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
		ctx: ctx, pool: pool,
		client: &http.Client{Timeout: 5 * time.Second},
		base:   srv.URL, srv: srv,
		roleRepo: roleRepo, userRepo: userRepo,
	}

	if err := cleanup(ctx, pool); err != nil {
		log.Fatalf("cleanup: %v", err)
	}
	defer func() { _ = cleanup(context.Background(), pool) }()
	if err := setupFixtures(ctx, e, authSvc); err != nil {
		log.Fatalf("setup: %v", err)
	}

	tests := []struct {
		name string
		fn   func(*env) error
	}{
		{"01 admin gate (all 23 routes pass)", testAdminGate},
		{"02 editor gate (8 pass, 15 forbidden)", testEditorGate},
		{"03 user gate (0 pass, 23 forbidden)", testUserGate},
		{"04 no-auth gate (all 23 routes → 401)", testNoAuth},
		{"05 NoRoute → 404 envelope", testNoRoute},
		{"06 malformed UUID → 400", testMalformedUUID},
		{"07 user CRUD (create/get/update/delete)", testUserCRUD},
		{"08 role CRUD (create/update/delete)", testRoleCRUD},
		{"09 permission CRUD (create/update/delete)", testPermCRUD},
	}

	for _, t := range tests {
		fmt.Printf("=== %s ===\n", t.name)
		if err := t.fn(e); err != nil {
			log.Fatalf("%s: %v", t.name, err)
		}
	}
	fmt.Println("ALL EXERCISES PASSED")
}

func setupFixtures(ctx context.Context, e *env, authSvc *service.AuthService) error {
	regs := []struct {
		email, role       string
		idStore, tokStore *string
	}{
		{adminEmail, "admin", &e.adminID, &e.adminTok},
		{editorEmail, "editor", &e.editorID, &e.editorTok},
		{userEmail, "", &e.userID, &e.userTok},
	}
	for _, r := range regs {
		u, err := authSvc.Register(ctx, service.RegisterInput{Email: r.email, Password: sharedPass, FullName: r.email})
		if err != nil {
			return fmt.Errorf("register %s: %w", r.email, err)
		}
		*r.idStore = u.ID.String()
		if r.role != "" {
			role, err := e.roleRepo.GetByName(ctx, e.pool, r.role)
			if err != nil {
				return err
			}
			if err := e.userRepo.AssignRole(ctx, e.pool, u.ID, role.ID); err != nil {
				return err
			}
		}
		pair, err := authSvc.Login(ctx, service.LoginInput{Email: r.email, Password: sharedPass}, nil, nil)
		if err != nil {
			return err
		}
		*r.tokStore = pair.AccessToken
	}
	return nil
}

func (e *env) do(method, path, body, bearer string) (int, []byte, error) {
	var rdr io.Reader
	if body != "" {
		rdr = bytes.NewBufferString(body)
	}
	req, err := http.NewRequestWithContext(e.ctx, method, e.base+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

func (e *env) expectErr(method, path, body, bearer string, wantStatus int, wantCode string) error {
	status, respBody, err := e.do(method, path, body, bearer)
	if err != nil {
		return err
	}
	if status != wantStatus {
		return fmt.Errorf("%s %s: status=%d want=%d body=%s", method, path, status, wantStatus, respBody)
	}
	if wantCode != "" {
		var env dto.ErrorEnvelope
		if err := json.Unmarshal(respBody, &env); err != nil {
			return fmt.Errorf("%s %s: unmarshal: %w", method, path, err)
		}
		if env.Error.Code != wantCode {
			return fmt.Errorf("%s %s: code=%q want=%q", method, path, env.Error.Code, wantCode)
		}
	}
	return nil
}

// expectGatePassed: not 401/403 (whatever the handler returns is fine).
func (e *env) expectGatePassed(method, path, body, bearer, who string) error {
	status, respBody, err := e.do(method, path, body, bearer)
	if err != nil {
		return err
	}
	if status == 401 || status == 403 {
		return fmt.Errorf("%s %s as %s: got %d, gate should pass. body=%s",
			method, path, who, status, respBody)
	}
	return nil
}

func cleanup(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx,
		`DELETE FROM audit_logs WHERE actor_user_id IN (SELECT id FROM users WHERE email IN ($1,$2,$3) OR email LIKE 'hc2-%')`,
		adminEmail, editorEmail, userEmail); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM users WHERE email IN ($1,$2,$3) OR email LIKE 'hc2-%'`,
		adminEmail, editorEmail, userEmail); err != nil {
		return err
	}
	for _, stmt := range []string{
		`DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE name LIKE 'hc2-%')`,
		`DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE name LIKE 'hc2-%')`,
		`DELETE FROM roles WHERE name LIKE 'hc2-%'`,
		`DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code LIKE 'hc2.%')`,
		`DELETE FROM permissions WHERE code LIKE 'hc2.%'`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// ---------- gate tests ----------

func allRoutes(e *env) []routeSpec {
	return []routeSpec{
		{"GET", "/api/v1/users", false, true},
		{"POST", "/api/v1/users", true, true},
		{"GET", "/api/v1/users/" + e.adminID, false, true},
		{"PATCH", "/api/v1/users/" + e.adminID, false, true},
		{"DELETE", "/api/v1/users/" + e.adminID, true, true},
		{"PATCH", "/api/v1/users/" + e.adminID + "/status", false, true},
		{"GET", "/api/v1/users/" + e.adminID + "/roles", false, true},
		{"POST", "/api/v1/users/" + e.adminID + "/roles", false, true},
		{"DELETE", "/api/v1/users/" + e.adminID + "/roles/" + e.adminID, false, true},
		{"GET", "/api/v1/users/" + e.adminID + "/permissions", false, true},
		{"GET", "/api/v1/roles", true, true},
		{"POST", "/api/v1/roles", true, true},
		{"GET", "/api/v1/roles/" + e.adminID, true, true},
		{"PATCH", "/api/v1/roles/" + e.adminID, true, true},
		{"DELETE", "/api/v1/roles/" + e.adminID, true, true},
		{"GET", "/api/v1/roles/" + e.adminID + "/permissions", true, true},
		{"POST", "/api/v1/roles/" + e.adminID + "/permissions", true, true},
		{"DELETE", "/api/v1/roles/" + e.adminID + "/permissions/" + e.adminID, true, true},
		{"GET", "/api/v1/permissions", true, true},
		{"POST", "/api/v1/permissions", true, true},
		{"GET", "/api/v1/permissions/" + e.adminID, true, true},
		{"PATCH", "/api/v1/permissions/" + e.adminID, true, true},
		{"DELETE", "/api/v1/permissions/" + e.adminID, true, true},
	}
}

func testAdminGate(e *env) error {
	for _, r := range allRoutes(e) {
		if err := e.expectGatePassed(r.method, r.path, `{}`, e.adminTok, "admin"); err != nil {
			return err
		}
	}
	fmt.Printf("admin passed all %d protected routes\n", len(allRoutes(e)))
	return nil
}

func testEditorGate(e *env) error {
	passes, forbids := 0, 0
	for _, r := range allRoutes(e) {
		if r.editorForbid {
			if err := e.expectErr(r.method, r.path, `{}`, e.editorTok, 403, dto.CodeForbidden); err != nil {
				return err
			}
			forbids++
		} else {
			if err := e.expectGatePassed(r.method, r.path, `{}`, e.editorTok, "editor"); err != nil {
				return err
			}
			passes++
		}
	}
	fmt.Printf("editor: %d pass, %d forbidden\n", passes, forbids)
	return nil
}

func testUserGate(e *env) error {
	passes, forbids := 0, 0
	for _, r := range allRoutes(e) {
		if r.userForbid {
			if err := e.expectErr(r.method, r.path, `{}`, e.userTok, 403, dto.CodeForbidden); err != nil {
				return err
			}
			forbids++
		} else {
			if err := e.expectGatePassed(r.method, r.path, `{}`, e.userTok, "user"); err != nil {
				return err
			}
			passes++
		}
	}
	fmt.Printf("user: %d pass, %d forbidden\n", passes, forbids)
	return nil
}

func testNoAuth(e *env) error {
	for _, r := range allRoutes(e) {
		if err := e.expectErr(r.method, r.path, "", "", 401, dto.CodeUnauthorized); err != nil {
			return err
		}
	}
	fmt.Printf("all %d protected routes return 401 without auth\n", len(allRoutes(e)))
	return nil
}

func testNoRoute(e *env) error {
	if err := e.expectErr("GET", "/api/v1/does-not-exist", "", "", 404, dto.CodeNotFound); err != nil {
		return err
	}
	fmt.Println("NoRoute → 404 envelope")
	return nil
}

func testMalformedUUID(e *env) error {
	if err := e.expectErr("GET", "/api/v1/users/not-a-uuid", "", e.adminTok, 400, dto.CodeInvalidInput); err != nil {
		return err
	}
	fmt.Println("malformed UUID → 400 invalid_input")
	return nil
}

// ---------- CRUD smoke tests ----------

func testUserCRUD(e *env) error {
	// Create
	status, body, err := e.do("POST", "/api/v1/users",
		`{"email":"hc2-crud-user@example.com","password":"`+sharedPass+`","full_name":"CRUD User"}`,
		e.adminTok)
	if err != nil {
		return err
	}
	if status != 201 {
		return fmt.Errorf("create: status=%d body=%s", status, body)
	}
	var u dto.UserView
	if err := json.Unmarshal(body, &u); err != nil {
		return err
	}

	// Get
	if err := e.expectGatePassed("GET", "/api/v1/users/"+u.ID, "", e.adminTok, "admin"); err != nil {
		return err
	}

	// Update
	status, body, err = e.do("PATCH", "/api/v1/users/"+u.ID, `{"full_name":"Renamed"}`, e.adminTok)
	if err != nil || status != 200 {
		return fmt.Errorf("update: status=%d body=%s", status, body)
	}

	// Delete
	if err := e.expectErr("DELETE", "/api/v1/users/"+u.ID, "", e.adminTok, 204, ""); err != nil {
		return err
	}

	fmt.Println("user CRUD: create/get/update/delete")
	return nil
}

func testRoleCRUD(e *env) error {
	status, body, err := e.do("POST", "/api/v1/roles", `{"name":"hc2-crud-role"}`, e.adminTok)
	if err != nil || status != 201 {
		return fmt.Errorf("create: status=%d body=%s", status, body)
	}
	var r dto.RoleView
	if err := json.Unmarshal(body, &r); err != nil {
		return err
	}

	status, body, err = e.do("PATCH", "/api/v1/roles/"+r.ID, `{"description":"test"}`, e.adminTok)
	if err != nil || status != 200 {
		return fmt.Errorf("update: status=%d body=%s", status, body)
	}

	if err := e.expectErr("DELETE", "/api/v1/roles/"+r.ID, "", e.adminTok, 204, ""); err != nil {
		return err
	}

	fmt.Println("role CRUD: create/update/delete")
	return nil
}

func testPermCRUD(e *env) error {
	status, body, err := e.do("POST", "/api/v1/permissions", `{"code":"hc2.crud.perm"}`, e.adminTok)
	if err != nil || status != 201 {
		return fmt.Errorf("create: status=%d body=%s", status, body)
	}
	var p dto.PermissionView
	if err := json.Unmarshal(body, &p); err != nil {
		return err
	}

	status, body, err = e.do("PATCH", "/api/v1/permissions/"+p.ID, `{"description":"test"}`, e.adminTok)
	if err != nil || status != 200 {
		return fmt.Errorf("update: status=%d body=%s", status, body)
	}

	if err := e.expectErr("DELETE", "/api/v1/permissions/"+p.ID, "", e.adminTok, 204, ""); err != nil {
		return err
	}

	fmt.Println("permission CRUD: create/update/delete")
	return nil
}
