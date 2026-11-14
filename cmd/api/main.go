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
	"time"

	"UserManagementSystem/internal/config"
	"UserManagementSystem/internal/database"
	"UserManagementSystem/internal/handler"
	"UserManagementSystem/internal/repository"
	"UserManagementSystem/internal/router"
	"UserManagementSystem/internal/security"
	"UserManagementSystem/internal/service"
)

func main() {
	// 1. Load config first — no logger yet, stderr on failure.
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "startup: %v\n", err)
		os.Exit(1)
	}
	setupLogger(cfg.Log)

	// 2. Root context cancelled on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 3. Database pool. Fail fast — never start without a DB.
	pool, err := database.NewPool(ctx, cfg.Database)
	if err != nil {
		slog.Error("db_init_failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	// 4. Auth primitives. The hasher pre-computes nothing at construction;
	// the AuthService will hash a dummy value itself.
	hasher := security.NewPasswordHasher(cfg.Auth.MaxConcurrentHashes)
	jwtIssuer := security.NewJWTIssuer(cfg.Auth.JWTSecret, cfg.Auth.JWTIssuer, cfg.Auth.AccessTokenTTL)

	// 5. Repositories.
	userRepo := repository.NewPGUserRepo()
	roleRepo := repository.NewPGRoleRepo()
	tokenRepo := repository.NewPGRefreshTokenRepo()

	// 6. Services. NoopAudit until Part 12.
	auditSvc := service.NewNoopAudit()
	authSvc, err := service.NewAuthService(
		pool, userRepo, tokenRepo, roleRepo,
		hasher, jwtIssuer, auditSvc,
		cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL,
	)
	if err != nil {
		slog.Error("auth_init_failed", "err", err)
		os.Exit(1)
	}

	// 7. Handlers.
	healthH := handler.NewHealthHandler(pool)
	authH := handler.NewAuthHandler(authSvc, cfg.Auth, cfg.Cookie)

	// 8. Adapters — bridge the DIP seam.
	verifier := security.JWTVerifierAdapter{Issuer: jwtIssuer}

	// 9. Router.
	r, err := router.New(healthH, authH, verifier, router.Options{
		Prod:           cfg.App.IsProd(),
		TrustedProxies: cfg.Server.TrustedProxies,
	})
	if err != nil {
		slog.Error("router_init_failed", "err", err)
		os.Exit(1)
	}

	// 10. HTTP server.
	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second, // Slowloris guard
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
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
