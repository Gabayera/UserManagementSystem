package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"UserManagementSystem/internal/config"
	"UserManagementSystem/internal/database"
	"UserManagementSystem/internal/dto"
	"UserManagementSystem/internal/middleware"
	"UserManagementSystem/internal/repository"
	"UserManagementSystem/internal/security"
	"UserManagementSystem/internal/service"
)

const (
	testEmail = "authzcheck@example.com"
	testPass  = "correct-horse-battery-staple"
)

var testUserID = uuid.MustParse("aaaa2222-0000-0000-0000-000000000001")

// ---------- demo router (per-resolver) ----------

func buildDemoRouter(resolver service.PermissionsResolver, verifier middleware.TokenVerifier) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(middleware.RequestID(), middleware.Logger(), middleware.Recovery())

	api := r.Group("/api/v1")
	protected := api.Group("/demo")
	protected.Use(middleware.Auth(verifier))
	protected.GET("/read", middleware.RequirePermission(resolver, "user.read"), demoOK)
	protected.GET("/delete", middleware.RequirePermission(resolver, "user.delete"), demoOK)
	protected.GET("/nonexistent", middleware.RequirePermission(resolver, "nonexistent.perm"), demoOK)
	return r
}

func demoOK(c *gin.Context) {
	c.String(http.StatusOK, "ok")
}

// ---------- fake resolvers ----------

type fakeErrorResolver struct{}

func (fakeErrorResolver) PermissionsForUser(ctx context.Context, userID uuid.UUID) (map[string]struct{}, error) {
	return nil, errors.New("simulated resolver outage")
}

type fakeEmptyResolver struct{}

func (fakeEmptyResolver) PermissionsForUser(ctx context.Context, userID uuid.UUID) (map[string]struct{}, error) {
	return map[string]struct{}{}, nil
}

var (
	_ service.PermissionsResolver = fakeErrorResolver{}
	_ service.PermissionsResolver = fakeEmptyResolver{}
)

// ---------- test environment ----------

type testEnv struct {
	ctx          context.Context
	pool         *pgxpool.Pool
	userRepo     repository.UserRepository
	roleRepo     *repository.PGRoleRepo
	authSvc      *service.AuthService
	jwtIssuer    *security.JWTIssuer
	jwtSecret    []byte // ← add this
	real         *httptest.Server
	fail         *httptest.Server
	empty        *httptest.Server
	client       *http.Client
	token        string
	userRoleID   uuid.UUID
	editorRoleID uuid.UUID
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
	tokenRepo := repository.NewPGRefreshTokenRepo()
	audit := service.NewNoopAudit()

	authSvc, err := service.NewAuthService(
		pool, userRepo, tokenRepo, roleRepo,
		hasher, jwtIssuer, audit,
		cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL,
	)
	if err != nil {
		log.Fatalf("auth svc: %v", err)
	}

	verifier := security.JWTVerifierAdapter{Issuer: jwtIssuer}
	realResolver := service.NewDBPermissionsResolver(pool, userRepo)

	realSrv := httptest.NewServer(buildDemoRouter(realResolver, verifier))
	defer realSrv.Close()
	failSrv := httptest.NewServer(buildDemoRouter(fakeErrorResolver{}, verifier))
	defer failSrv.Close()
	emptySrv := httptest.NewServer(buildDemoRouter(fakeEmptyResolver{}, verifier))
	defer emptySrv.Close()

	e := &testEnv{
		ctx:       ctx,
		pool:      pool,
		userRepo:  userRepo,
		roleRepo:  roleRepo,
		authSvc:   authSvc,
		jwtIssuer: jwtIssuer,
		jwtSecret: cfg.Auth.JWTSecret, // ← add this
		real:      realSrv,
		fail:      failSrv,
		empty:     emptySrv,
		client:    &http.Client{Timeout: 5 * time.Second},
	}

	if err := cleanup(ctx, pool); err != nil {
		log.Fatalf("cleanup: %v", err)
	}
	defer func() {
		if err := cleanup(context.Background(), pool); err != nil {
			fmt.Println("CLEANUP FAILED:", err)
		}
	}()

	// Setup: register, look up seeded roles, login → token.
	user, err := authSvc.Register(ctx, service.RegisterInput{
		Email: testEmail, Password: testPass, FullName: "Authz Check",
	})
	if err != nil {
		log.Fatalf("setup register: %v", err)
	}
	e.token = ""
	if user.ID != testUserID {
		// Register generated its own UUID; use whatever it returned.
		testUserID = user.ID
	}
	pair, err := authSvc.Login(ctx, service.LoginInput{Email: testEmail, Password: testPass}, nil, nil)
	if err != nil {
		log.Fatalf("setup login: %v", err)
	}
	e.token = pair.AccessToken

	userRole, err := roleRepo.GetByName(ctx, pool, "user")
	if err != nil {
		log.Fatalf("lookup user role: %v", err)
	}
	e.userRoleID = userRole.ID
	editor, err := roleRepo.GetByName(ctx, pool, "editor")
	if err != nil {
		log.Fatalf("lookup editor role: %v", err)
	}
	e.editorRoleID = editor.ID

	tests := []struct {
		name string
		fn   func(*testEnv) error
	}{
		{"01 no auth → 401", ex01},
		{"02 garbage bearer → 401", ex02},
		{"03 valid bearer, /read → 200", ex03},
		{"04 valid bearer, /delete → 403", ex04},
		{"05 remove user role, /read → 403", ex05},
		{"06 assign editor role, same token /read → 200", ex06},
		{"07 unknown permission code → 403", ex07},
		{"08 resolver error → 500 (FAIL-CLOSED)", ex08},
		{"09 resolver error but no bearer → 401 (Auth first)", ex09},
		{"10 empty resolver → 403 (DEFAULT DENY)", ex10},
		{"11 expired bearer → 401", ex11},
		{"12 wrong-secret bearer → 401", ex12},
		{"13 same token, DB change, outcome changes", ex13},
	}

	for _, t := range tests {
		fmt.Printf("=== %s ===\n", t.name)
		if err := t.fn(e); err != nil {
			log.Fatalf("%s: %v", t.name, err)
		}
	}
	fmt.Println("ALL EXERCISES PASSED")
}

// ---------- helpers ----------

func (e *testEnv) do(base, path, bearer string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(e.ctx, "GET", base+path, nil)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

func expectErrCode(status int, body []byte, wantStatus int, wantCode string) error {
	if status != wantStatus {
		return fmt.Errorf("status=%d want=%d body=%s", status, wantStatus, body)
	}
	var env dto.ErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("unmarshal: %w body=%s", err, body)
	}
	if env.Error.Code != wantCode {
		return fmt.Errorf("code=%q want=%q body=%s", env.Error.Code, wantCode, body)
	}
	return nil
}

func cleanup(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx,
		`DELETE FROM audit_logs WHERE actor_user_id = $1 OR actor_user_id = (SELECT id FROM users WHERE email = $2)`,
		testUserID, testEmail); err != nil {
		return err
	}
	_, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1 OR email = $2`, testUserID, testEmail)
	return err
}

// ---------- test cases ----------

func ex01(e *testEnv) error {
	status, body, err := e.do(e.real.URL, "/api/v1/demo/read", "")
	if err != nil {
		return err
	}
	if err := expectErrCode(status, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	fmt.Println("no auth: 401 unauthorized")
	return nil
}

func ex02(e *testEnv) error {
	status, body, err := e.do(e.real.URL, "/api/v1/demo/read", "garbage-not-a-jwt")
	if err != nil {
		return err
	}
	if err := expectErrCode(status, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	fmt.Println("garbage bearer: 401 unauthorized")
	return nil
}

func ex03(e *testEnv) error {
	status, body, err := e.do(e.real.URL, "/api/v1/demo/read", e.token)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("status=%d want=200 body=%s", status, body)
	}
	fmt.Println("valid bearer + user.read: 200")
	return nil
}

func ex04(e *testEnv) error {
	status, body, err := e.do(e.real.URL, "/api/v1/demo/delete", e.token)
	if err != nil {
		return err
	}
	if err := expectErrCode(status, body, 403, dto.CodeForbidden); err != nil {
		return err
	}
	fmt.Println("valid bearer + no user.delete: 403 forbidden")
	return nil
}

func ex05(e *testEnv) error {
	if err := e.userRepo.RemoveRole(e.ctx, e.pool, testUserID, e.userRoleID); err != nil {
		return err
	}
	status, body, err := e.do(e.real.URL, "/api/v1/demo/read", e.token)
	if err != nil {
		return err
	}
	if err := expectErrCode(status, body, 403, dto.CodeForbidden); err != nil {
		return err
	}
	fmt.Println("role removed, same token: 403 forbidden (DB read, not claims)")
	return nil
}

func ex06(e *testEnv) error {
	if err := e.userRepo.AssignRole(e.ctx, e.pool, testUserID, e.editorRoleID); err != nil {
		return err
	}
	status, body, err := e.do(e.real.URL, "/api/v1/demo/read", e.token)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("status=%d want=200 body=%s", status, body)
	}
	fmt.Println("editor assigned, same token: 200 (dynamic resolution)")
	return nil
}

func ex07(e *testEnv) error {
	status, body, err := e.do(e.real.URL, "/api/v1/demo/nonexistent", e.token)
	if err != nil {
		return err
	}
	if err := expectErrCode(status, body, 403, dto.CodeForbidden); err != nil {
		return err
	}
	fmt.Println("unknown permission code: 403 forbidden")
	return nil
}

func ex08(e *testEnv) error {
	status, body, err := e.do(e.fail.URL, "/api/v1/demo/read", e.token)
	if err != nil {
		return err
	}
	// Fail-closed: must NOT be 200.
	if status == 200 {
		return fmt.Errorf("FAIL-CLOSED VIOLATED: resolver error returned 200 (body=%s)", body)
	}
	// Expect 5xx family.
	if status < 500 || status >= 600 {
		return fmt.Errorf("expected 5xx from resolver outage, got %d body=%s", status, body)
	}
	fmt.Printf("resolver error: %d (fail-closed, not 200)\n", status)
	return nil
}

func ex09(e *testEnv) error {
	status, body, err := e.do(e.fail.URL, "/api/v1/demo/read", "")
	if err != nil {
		return err
	}
	if err := expectErrCode(status, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	fmt.Println("resolver error but no auth: 401 (Auth runs first)")
	return nil
}

func ex10(e *testEnv) error {
	status, body, err := e.do(e.empty.URL, "/api/v1/demo/read", e.token)
	if err != nil {
		return err
	}
	if err := expectErrCode(status, body, 403, dto.CodeForbidden); err != nil {
		return err
	}
	fmt.Println("empty resolver: 403 forbidden (default deny)")
	return nil
}

func ex11(e *testEnv) error {
	// JWTIssuer.Verify applies a 30-second leeway on `exp` (Part 7 design;
	// OWASP-recommended for clock skew). To prove expiry is *enforced*, the
	// test token must be expired by MORE than the leeway window. We use
	// -60s TTL so `exp` is 60 seconds in the past — well beyond 30s.
	expiredIssuer := security.NewJWTIssuer(
		e.jwtSecret,
		"user-management-system",
		-60*time.Second,
	)
	expired, _, exp, err := expiredIssuer.Sign(testUserID)
	if err != nil {
		return err
	}
	if exp.After(time.Now()) {
		return fmt.Errorf("test setup bug: token not expired (exp=%v now=%v)", exp, time.Now())
	}

	status, body, err := e.do(e.real.URL, "/api/v1/demo/read", expired)
	if err != nil {
		return err
	}
	if err := expectErrCode(status, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	fmt.Printf("expired bearer (exp %v ago): 401 unauthorized\n",
		time.Since(exp).Round(time.Second))
	return nil
}

func ex12(e *testEnv) error {
	wrong := security.NewJWTIssuer(
		[]byte("a-different-secret-that-is-at-least-32-bytes-long"),
		"user-management-system", 15*time.Minute,
	)
	wrongTok, _, _, err := wrong.Sign(testUserID)
	if err != nil {
		return err
	}
	status, body, err := e.do(e.real.URL, "/api/v1/demo/read", wrongTok)
	if err != nil {
		return err
	}
	if err := expectErrCode(status, body, 401, dto.CodeUnauthorized); err != nil {
		return err
	}
	fmt.Println("wrong-secret bearer: 401 unauthorized")
	return nil
}

func ex13(e *testEnv) error {
	// Current state from ex06: user has "editor" (has user.read).
	// Remove it and verify 403 — same token throughout.
	if err := e.userRepo.RemoveRole(e.ctx, e.pool, testUserID, e.editorRoleID); err != nil {
		return err
	}
	status, body, err := e.do(e.real.URL, "/api/v1/demo/read", e.token)
	if err != nil {
		return err
	}
	if err := expectErrCode(status, body, 403, dto.CodeForbidden); err != nil {
		return err
	}
	fmt.Println("after removing editor (same token): 403")
	return nil
}
