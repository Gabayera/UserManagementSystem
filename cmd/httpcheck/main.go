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

	adminTok  string
	editorTok string
	userTok   string

	adminID  string
	editorID string
	userID   string
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
	audit := service.NewNoopAudit()

	authSvc, err := service.NewAuthService(
		pool, userRepo, tokenRepo, roleRepo, hasher, jwtIssuer, audit,
		cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL,
	)
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
		verifier,
		resolver,
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
		{"A.01 all protected routes → 401 without auth", sectionA},
		{"B.01 admin passes every protected route", sectionB},
		{"C.01 editor forbidden on role/permission routes", sectionC1},
		{"C.02 editor forbidden on user.create/delete", sectionC2},
		{"C.03 user forbidden on user.update/delete", sectionC3},
		{"D.01 NoRoute → 404 envelope", sectionD1},
		{"D.02 malformed UUID → 400 not 404", sectionD2},
		{"E.01 create user via admin", sectionE1},
		{"E.02 get created user", sectionE2},
		{"E.03 update user full_name", sectionE3},
		{"E.04 deactivate + reactivate", sectionE4},
		{"E.05 list user roles", sectionE5},
		{"E.06 assign + remove role", sectionE6},
		{"E.07 delete user", sectionE7},
		{"E.08 deleted user → 404", sectionE8},
		{"F.01 create test role", sectionF1},
		{"F.02 update test role", sectionF2},
		{"F.03 add + list + remove permission", sectionF3},
		{"F.04 delete test role", sectionF4},
		{"G.01 create test permission", sectionG1},
		{"G.02 update test permission", sectionG2},
		{"G.03 delete test permission", sectionG3},
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
		email, role string
		idStore     *string
		tokStore    *string
	}{
		{adminEmail, "admin", &e.adminID, &e.adminTok},
		{editorEmail, "editor", &e.editorID, &e.editorTok},
		{userEmail, "", &e.userID, &e.userTok},
	}
	for _, r := range regs {
		u, err := authSvc.Register(ctx, service.RegisterInput{
			Email: r.email, Password: sharedPass, FullName: r.email,
		})
		if err != nil {
			return fmt.Errorf("register %s: %w", r.email, err)
		}
		*r.idStore = u.ID.String()
		if r.role != "" {
			role, err := e.roleRepo.GetByName(ctx, e.pool, r.role)
			if err != nil {
				return fmt.Errorf("lookup role %s: %w", r.role, err)
			}
			if err := e.userRepo.AssignRole(ctx, e.pool, u.ID, role.ID); err != nil {
				return err
			}
		}
		pair, err := authSvc.Login(ctx, service.LoginInput{Email: r.email, Password: sharedPass}, nil, nil)
		if err != nil {
			return fmt.Errorf("login %s: %w", r.email, err)
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

func (e *env) doExpectErr(method, path, body, bearer string, wantStatus int, wantCode string) error {
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
			return fmt.Errorf("%s %s: unmarshal: %w body=%s", method, path, err, respBody)
		}
		if env.Error.Code != wantCode {
			return fmt.Errorf("%s %s: code=%q want=%q body=%s", method, path, env.Error.Code, wantCode, respBody)
		}
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
	if _, err := pool.Exec(ctx, `DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE name LIKE 'hc2-%')`); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `DELETE FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE name LIKE 'hc2-%')`); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `DELETE FROM roles WHERE name LIKE 'hc2-%'`); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE code LIKE 'hc2.%')`); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `DELETE FROM permissions WHERE code LIKE 'hc2.%'`); err != nil {
		return err
	}
	return nil
}

func sectionA(e *env) error {
	type route struct{ method, path string }
	routes := []route{
		{"GET", "/api/v1/users"},
		{"POST", "/api/v1/users"},
		{"GET", "/api/v1/users/" + e.adminID},
		{"PATCH", "/api/v1/users/" + e.adminID},
		{"DELETE", "/api/v1/users/" + e.adminID},
		{"PATCH", "/api/v1/users/" + e.adminID + "/status"},
		{"GET", "/api/v1/users/" + e.adminID + "/roles"},
		{"POST", "/api/v1/users/" + e.adminID + "/roles"},
		{"DELETE", "/api/v1/users/" + e.adminID + "/roles/" + e.adminID},
		{"GET", "/api/v1/users/" + e.adminID + "/permissions"},
		{"GET", "/api/v1/roles"},
		{"POST", "/api/v1/roles"},
		{"GET", "/api/v1/roles/" + e.adminID},
		{"PATCH", "/api/v1/roles/" + e.adminID},
		{"DELETE", "/api/v1/roles/" + e.adminID},
		{"GET", "/api/v1/roles/" + e.adminID + "/permissions"},
		{"POST", "/api/v1/roles/" + e.adminID + "/permissions"},
		{"DELETE", "/api/v1/roles/" + e.adminID + "/permissions/" + e.adminID},
		{"GET", "/api/v1/permissions"},
		{"POST", "/api/v1/permissions"},
		{"GET", "/api/v1/permissions/" + e.adminID},
		{"PATCH", "/api/v1/permissions/" + e.adminID},
		{"DELETE", "/api/v1/permissions/" + e.adminID},
	}
	for _, rt := range routes {
		if err := e.doExpectErr(rt.method, rt.path, "", "", 401, dto.CodeUnauthorized); err != nil {
			return err
		}
	}
	fmt.Printf("%d protected routes all return 401 without auth\n", len(routes))
	return nil
}

func sectionB(e *env) error {
	type route struct{ method, path, body string }
	routes := []route{
		{"GET", "/api/v1/users", ""},
		{"POST", "/api/v1/users", `{"email":"hc2-b1@example.com","password":"` + sharedPass + `","full_name":"B1"}`},
		{"GET", "/api/v1/users/" + e.adminID, ""},
		{"PATCH", "/api/v1/users/" + e.adminID, `{}`},
		{"PATCH", "/api/v1/users/" + e.adminID + "/status", `{"is_active":true}`},
		{"GET", "/api/v1/users/" + e.adminID + "/roles", ""},
		{"GET", "/api/v1/users/" + e.adminID + "/permissions", ""},
		{"GET", "/api/v1/roles", ""},
		{"POST", "/api/v1/roles", `{"name":"hc2-b-role"}`},
		{"GET", "/api/v1/roles/" + e.adminID, ""},
		{"PATCH", "/api/v1/roles/" + e.adminID, `{}`},
		{"GET", "/api/v1/roles/" + e.adminID + "/permissions", ""},
		{"GET", "/api/v1/permissions", ""},
		{"POST", "/api/v1/permissions", `{"code":"hc2.b.perm"}`},
		{"GET", "/api/v1/permissions/" + e.adminID, ""},
		{"PATCH", "/api/v1/permissions/" + e.adminID, `{}`},
	}
	for _, rt := range routes {
		status, body, err := e.do(rt.method, rt.path, rt.body, e.adminTok)
		if err != nil {
			return err
		}
		if status == 401 || status == 403 {
			return fmt.Errorf("admin got %d on %s %s — admin should be allowed. body=%s",
				status, rt.method, rt.path, body)
		}
	}
	fmt.Printf("admin passed %d routes without 401/403\n", len(routes))
	return nil
}

func sectionC1(e *env) error {
	check := []struct{ method, path string }{
		{"GET", "/api/v1/roles"},
		{"POST", "/api/v1/roles"},
		{"GET", "/api/v1/permissions"},
		{"POST", "/api/v1/permissions"},
	}
	for _, rt := range check {
		if err := e.doExpectErr(rt.method, rt.path, "", e.editorTok, 403, dto.CodeForbidden); err != nil {
			return err
		}
	}
	fmt.Printf("editor got 403 on %d role/permission routes\n", len(check))
	return nil
}

func sectionC2(e *env) error {
	check := []struct {
		method, path, body string
	}{
		{"POST", "/api/v1/users", `{"email":"x@y.com","password":"` + sharedPass + `","full_name":"x"}`},
		{"DELETE", "/api/v1/users/" + e.adminID, ""},
	}
	for _, rt := range check {
		if err := e.doExpectErr(rt.method, rt.path, rt.body, e.editorTok, 403, dto.CodeForbidden); err != nil {
			return err
		}
	}
	fmt.Printf("editor got 403 on %d user.create/delete routes\n", len(check))
	return nil
}

func sectionC3(e *env) error {
	check := []struct {
		method, path, body string
	}{
		{"POST", "/api/v1/users", `{"email":"x@y.com","password":"` + sharedPass + `","full_name":"x"}`},
		{"PATCH", "/api/v1/users/" + e.adminID, `{}`},
		{"DELETE", "/api/v1/users/" + e.adminID, ""},
		{"GET", "/api/v1/roles", ""},
		{"GET", "/api/v1/permissions", ""},
	}
	for _, rt := range check {
		if err := e.doExpectErr(rt.method, rt.path, rt.body, e.userTok, 403, dto.CodeForbidden); err != nil {
			return err
		}
	}
	fmt.Printf("plain user got 403 on %d privileged routes\n", len(check))
	return nil
}

func sectionD1(e *env) error {
	if err := e.doExpectErr("GET", "/api/v1/does-not-exist", "", "", 404, dto.CodeNotFound); err != nil {
		return err
	}
	fmt.Println("NoRoute → 404 envelope")
	return nil
}

func sectionD2(e *env) error {
	if err := e.doExpectErr("GET", "/api/v1/users/not-a-uuid", "", e.adminTok, 400, dto.CodeInvalidInput); err != nil {
		return err
	}
	fmt.Println("malformed UUID → 400 invalid_input (not 404)")
	return nil
}

var createdUserID string

func sectionE1(e *env) error {
	status, body, err := e.do("POST", "/api/v1/users",
		`{"email":"hc2-target@example.com","password":"`+sharedPass+`","full_name":"HC2 Target"}`,
		e.adminTok)
	if err != nil {
		return err
	}
	if status != 201 {
		return fmt.Errorf("status=%d body=%s", status, body)
	}
	var u dto.UserView
	if err := json.Unmarshal(body, &u); err != nil {
		return err
	}
	createdUserID = u.ID
	fmt.Printf("created: id=%s\n", u.ID)
	return nil
}

func sectionE2(e *env) error {
	status, body, err := e.do("GET", "/api/v1/users/"+createdUserID, "", e.adminTok)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("status=%d body=%s", status, body)
	}
	var u dto.UserView
	if err := json.Unmarshal(body, &u); err != nil {
		return err
	}
	if u.FullName != "HC2 Target" {
		return fmt.Errorf("full_name=%q", u.FullName)
	}
	fmt.Println("get user → 200")
	return nil
}

func sectionE3(e *env) error {
	status, body, err := e.do("PATCH", "/api/v1/users/"+createdUserID,
		`{"full_name":"HC2 Renamed"}`, e.adminTok)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("status=%d body=%s", status, body)
	}
	var u dto.UserView
	if err := json.Unmarshal(body, &u); err != nil {
		return err
	}
	if u.FullName != "HC2 Renamed" {
		return fmt.Errorf("full_name=%q", u.FullName)
	}
	fmt.Println("update user → 200")
	return nil
}

func sectionE4(e *env) error {
	if err := e.doExpectErr("PATCH", "/api/v1/users/"+createdUserID+"/status",
		`{"is_active":false}`, e.adminTok, 204, ""); err != nil {
		return err
	}
	if err := e.doExpectErr("PATCH", "/api/v1/users/"+createdUserID+"/status",
		`{"is_active":true}`, e.adminTok, 204, ""); err != nil {
		return err
	}
	fmt.Println("deactivate + reactivate → 204")
	return nil
}

func sectionE5(e *env) error {
	status, body, err := e.do("GET", "/api/v1/users/"+createdUserID+"/roles", "", e.adminTok)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("status=%d body=%s", status, body)
	}
	var resp dto.UserRolesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return err
	}
	hasUserRole := false
	for _, r := range resp.Roles {
		if r.Name == "user" {
			hasUserRole = true
		}
	}
	if !hasUserRole {
		return fmt.Errorf("expected 'user' role, got %v", resp.Roles)
	}
	fmt.Printf("get roles → 200, %d roles\n", len(resp.Roles))
	return nil
}

func sectionE6(e *env) error {
	editor, err := e.roleRepo.GetByName(e.ctx, e.pool, "editor")
	if err != nil {
		return err
	}
	status, body, err := e.do("POST", "/api/v1/users/"+createdUserID+"/roles",
		`{"role_id":"`+editor.ID.String()+`"}`, e.adminTok)
	if err != nil {
		return err
	}
	if status != 204 {
		return fmt.Errorf("assign status=%d body=%s", status, body)
	}
	status, body, err = e.do("GET", "/api/v1/users/"+createdUserID+"/roles", "", e.adminTok)
	if err != nil {
		return err
	}
	var resp dto.UserRolesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return err
	}
	if len(resp.Roles) != 2 {
		return fmt.Errorf("after assign: %d roles, expected 2", len(resp.Roles))
	}
	status, body, err = e.do("DELETE", "/api/v1/users/"+createdUserID+"/roles/"+editor.ID.String(),
		"", e.adminTok)
	if err != nil {
		return err
	}
	if status != 204 {
		return fmt.Errorf("remove status=%d body=%s", status, body)
	}
	fmt.Println("assign + remove role → 204 both")
	return nil
}

func sectionE7(e *env) error {
	if err := e.doExpectErr("DELETE", "/api/v1/users/"+createdUserID, "", e.adminTok, 204, ""); err != nil {
		return err
	}
	fmt.Println("delete user → 204")
	return nil
}

func sectionE8(e *env) error {
	if err := e.doExpectErr("GET", "/api/v1/users/"+createdUserID, "", e.adminTok, 404, dto.CodeNotFound); err != nil {
		return err
	}
	fmt.Println("deleted user → 404")
	return nil
}

var createdRoleID string

func sectionF1(e *env) error {
	status, body, err := e.do("POST", "/api/v1/roles", `{"name":"hc2-test-role"}`, e.adminTok)
	if err != nil {
		return err
	}
	if status != 201 {
		return fmt.Errorf("status=%d body=%s", status, body)
	}
	var r dto.RoleView
	if err := json.Unmarshal(body, &r); err != nil {
		return err
	}
	createdRoleID = r.ID
	fmt.Printf("created role: id=%s\n", r.ID)
	return nil
}

func sectionF2(e *env) error {
	desc := "updated description"
	descJSON, _ := json.Marshal(desc)
	status, body, err := e.do("PATCH", "/api/v1/roles/"+createdRoleID,
		`{"description":`+string(descJSON)+`}`, e.adminTok)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("status=%d body=%s", status, body)
	}
	var r dto.RoleView
	if err := json.Unmarshal(body, &r); err != nil {
		return err
	}
	if r.Description == nil || *r.Description != desc {
		return fmt.Errorf("description=%v", r.Description)
	}
	fmt.Println("update role → 200")
	return nil
}

func sectionF3(e *env) error {
	status, body, err := e.do("GET", "/api/v1/permissions?limit=1", "", e.adminTok)
	if err != nil || status != 200 {
		return fmt.Errorf("list perms: status=%d body=%s err=%v", status, body, err)
	}
	var plist dto.PermissionListResponse
	if err := json.Unmarshal(body, &plist); err != nil {
		return err
	}
	if len(plist.Permissions) == 0 {
		return fmt.Errorf("no permissions available")
	}
	permID := plist.Permissions[0].ID

	if err := e.doExpectErr("POST", "/api/v1/roles/"+createdRoleID+"/permissions",
		`{"permission_id":"`+permID+`"}`, e.adminTok, 204, ""); err != nil {
		return err
	}
	status, body, err = e.do("GET", "/api/v1/roles/"+createdRoleID+"/permissions", "", e.adminTok)
	if err != nil || status != 200 {
		return fmt.Errorf("list: status=%d body=%s", status, body)
	}
	var rlist dto.RolePermissionsResponse
	if err := json.Unmarshal(body, &rlist); err != nil {
		return err
	}
	if len(rlist.Permissions) != 1 {
		return fmt.Errorf("expected 1 permission, got %d", len(rlist.Permissions))
	}
	if err := e.doExpectErr("DELETE", "/api/v1/roles/"+createdRoleID+"/permissions/"+permID,
		"", e.adminTok, 204, ""); err != nil {
		return err
	}
	fmt.Println("add + list + remove permission → all 2xx")
	return nil
}

func sectionF4(e *env) error {
	if err := e.doExpectErr("DELETE", "/api/v1/roles/"+createdRoleID, "", e.adminTok, 204, ""); err != nil {
		return err
	}
	fmt.Println("delete role → 204")
	return nil
}

var createdPermID string

func sectionG1(e *env) error {
	status, body, err := e.do("POST", "/api/v1/permissions", `{"code":"hc2.test.perm"}`, e.adminTok)
	if err != nil {
		return err
	}
	if status != 201 {
		return fmt.Errorf("status=%d body=%s", status, body)
	}
	var p dto.PermissionView
	if err := json.Unmarshal(body, &p); err != nil {
		return err
	}
	createdPermID = p.ID
	fmt.Printf("created permission: id=%s code=%s\n", p.ID, p.Code)
	return nil
}

func sectionG2(e *env) error {
	desc := "updated description"
	descJSON, _ := json.Marshal(desc)
	status, body, err := e.do("PATCH", "/api/v1/permissions/"+createdPermID,
		`{"description":`+string(descJSON)+`}`, e.adminTok)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("status=%d body=%s", status, body)
	}
	fmt.Println("update permission → 200")
	return nil
}

func sectionG3(e *env) error {
	if err := e.doExpectErr("DELETE", "/api/v1/permissions/"+createdPermID, "", e.adminTok, 204, ""); err != nil {
		return err
	}
	fmt.Println("delete permission → 204")
	return nil
}
