package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"UserManagementSystem/internal/config"
	"UserManagementSystem/internal/database"
	"UserManagementSystem/internal/handler"
	"UserManagementSystem/internal/repository"
	"UserManagementSystem/internal/router"
	"UserManagementSystem/internal/security"
	"UserManagementSystem/internal/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "startup: %v\n", err)
		os.Exit(1)
	}
	setupLogger(cfg.Log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.NewPool(ctx, cfg.Database)
	if err != nil {
		slog.Error("db_init_failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

<<<<<<< HEAD
	hasher := security.NewPasswordHasher(cfg.Auth.MaxConcurrentHashes)
	jwtIssuer := security.NewJWTIssuer(cfg.Auth.JWTSecret, cfg.Auth.JWTIssuer, cfg.Auth.AccessTokenTTL)

=======
	// 4. Auth primitives.
	hasher := security.NewPasswordHasher(cfg.Auth.MaxConcurrentHashes)
	jwtIssuer := security.NewJWTIssuer(cfg.Auth.JWTSecret, cfg.Auth.JWTIssuer, cfg.Auth.AccessTokenTTL)

	// 5. Repositories and services.
>>>>>>> 72e85af53a6add245619a68d7c41454746c6adf7
	userRepo := repository.NewPGUserRepo()
	roleRepo := repository.NewPGRoleRepo()
	permRepo := repository.NewPGPermissionRepo()
	tokenRepo := repository.NewPGRefreshTokenRepo()
<<<<<<< HEAD
	auditRepo := repository.NewPGAuditLogRepo()

	auditSvc := service.NewRealAudit(pool, auditRepo)

=======
	auditSvc := service.NewNoopAudit()
>>>>>>> 72e85af53a6add245619a68d7c41454746c6adf7
	authSvc, err := service.NewAuthService(
		pool, userRepo, tokenRepo, roleRepo,
		hasher, jwtIssuer, auditSvc,
		cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL,
	)
	if err != nil {
		slog.Error("auth_init_failed", "err", err)
		os.Exit(1)
	}

<<<<<<< HEAD
	userSvc := service.NewUserService(pool, userRepo, roleRepo, hasher, auditSvc)
	roleSvc := service.NewRoleService(pool, roleRepo, auditSvc)
	permSvc := service.NewPermissionService(pool, permRepo, auditSvc)
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
=======
	// 6. Handlers and router.
	healthH := handler.NewHealthHandler(pool)
	authH := handler.NewAuthHandler(authSvc, cfg.Auth, cfg.Cookie)
	verifier := security.JWTVerifierAdapter{Issuer: jwtIssuer}
	r, err := router.New(healthH, authH, verifier, router.Options{
		Prod:           cfg.App.IsProd(),
		TrustedProxies: cfg.Server.TrustedProxies,
	})
	if err != nil {
		slog.Error("router_init_failed", "err", err)
		os.Exit(1)
	}
>>>>>>> 72e85af53a6add245619a68d7c41454746c6adf7

	srv := &http.Server{
		Addr:         cfg.Server.Addr,
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server_listen_failed", "err", err)
			stop()
		}
	}()
	slog.Info("server_started", "addr", cfg.Server.Addr, "env", cfg.App.Env)

	<-ctx.Done()
	slog.Info("shutdown_initiated")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("shutdown_error", "err", err)
	}
	slog.Info("shutdown_complete")
}

func setupLogger(cfg config.LogConfig) {
	var lvl slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.ToLower(cfg.Format) == "json" {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(h))
}
