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

	hasher := security.NewPasswordHasher(cfg.Auth.MaxConcurrentHashes)
	jwtIssuer := security.NewJWTIssuer(cfg.Auth.JWTSecret, cfg.Auth.JWTIssuer, cfg.Auth.AccessTokenTTL)

	userRepo := repository.NewPGUserRepo()
	roleRepo := repository.NewPGRoleRepo()
	permRepo := repository.NewPGPermissionRepo()
	tokenRepo := repository.NewPGRefreshTokenRepo()
	auditRepo := repository.NewPGAuditLogRepo()

	auditSvc := service.NewRealAudit(pool, auditRepo)

	authSvc, err := service.NewAuthService(
		pool, userRepo, tokenRepo, roleRepo,
		hasher, jwtIssuer, auditSvc,
		cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL,
	)
	if err != nil {
		slog.Error("auth_init_failed", "err", err)
		os.Exit(1)
	}

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

	srv := &http.Server{
		Addr:         cfg.Server.Addr,
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	listenErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
			stop()
		}
	}()
	slog.Info("server_started", "addr", cfg.Server.Addr, "env", cfg.App.Env)

	<-ctx.Done()
	slog.Info("shutdown_initiated")

	var exitCode int
	select {
	case err := <-listenErr:
		slog.Error("server_listen_failed", "err", err)
		exitCode = 1
	default:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("shutdown_error", "err", err)
	}
	slog.Info("shutdown_complete")
	if exitCode != 0 {
		pool.Close() // os.Exit skips defers
		os.Exit(exitCode)
	}
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
