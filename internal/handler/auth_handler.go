package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"UserManagementSystem/internal/apiresp"
	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/config"
	"UserManagementSystem/internal/domain"
	"UserManagementSystem/internal/dto"
	"UserManagementSystem/internal/middleware"
	"UserManagementSystem/internal/service"
)

// authService is the narrow slice of *service.AuthService that this handler
// needs. Defined at the consumer (ISP). AuthService can grow methods for
// other consumers without touching this file.
type authService interface {
	Register(ctx context.Context, in service.RegisterInput) (*domain.User, error)
	Login(ctx context.Context, in service.LoginInput, ua, ip *string) (*service.TokenPair, error)
	Refresh(ctx context.Context, rawToken string, ua, ip *string) (*service.TokenPair, error)
	Logout(ctx context.Context, rawToken string) error
	LogoutAll(ctx context.Context, userID uuid.UUID) error
	Me(ctx context.Context, userID uuid.UUID) (*service.MeOutput, error)
}

// AuthHandler is the HTTP translation layer for /api/v1/auth/*. It has no
// business logic — every decision is either "which DTO to bind" or "which
// status code" (and the latter is delegated to apiresp).
type AuthHandler struct {
	auth      authService
	authCfg   config.AuthConfig
	cookieCfg config.CookieConfig
}

func NewAuthHandler(auth authService, authCfg config.AuthConfig, cookieCfg config.CookieConfig) *AuthHandler {
	return &AuthHandler{auth: auth, authCfg: authCfg, cookieCfg: cookieCfg}
}

const refreshCookieName = "refresh_token"

// ---------- handlers ----------

func (h *AuthHandler) Register(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	var req dto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresp.RespondValidation(c, requestID)
		return
	}
	u, err := h.auth.Register(c.Request.Context(), service.RegisterInput{
		Email: req.Email, Password: req.Password, FullName: req.FullName,
	})
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusCreated, toRegisterResponse(u))
}

func (h *AuthHandler) Login(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	var req dto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresp.RespondValidation(c, requestID)
		return
	}
	ua := c.Request.UserAgent()
	ip := c.ClientIP()
	pair, err := h.auth.Login(c.Request.Context(), service.LoginInput{
		Email: req.Email, Password: req.Password,
	}, &ua, &ip)
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	h.setRefreshCookie(c, pair.RefreshToken)
	c.JSON(http.StatusOK, toLoginResponse(pair))
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	raw, fromBody := h.readRefreshToken(c)
	if raw == "" {
		apiresp.Respond(c, apperr.ErrUnauthorized, requestID)
		return
	}
	ua := c.Request.UserAgent()
	ip := c.ClientIP()
	pair, err := h.auth.Refresh(c.Request.Context(), raw, &ua, &ip)
	if err != nil {
		// Clear the cookie only when the token is definitively dead
		// (revoked / expired / reuse / user gone → 401). A transient failure
		// (DB down → 500/503/504) must NOT log the user out: the cookie is
		// still valid and the client can simply retry.
		if errors.Is(err, apperr.ErrUnauthorized) || errors.Is(err, apperr.ErrForbidden) {
			h.clearRefreshCookie(c)
		}
		apiresp.Respond(c, err, requestID)
		return
	}
	h.setRefreshCookie(c, pair.RefreshToken)
	c.JSON(http.StatusOK, toRefreshResponse(pair, fromBody))
}

// Logout is idempotent — always returns 204 regardless of cookie state or
// service outcome. Service errors are swallowed (already logged inside), and
// the client always sees its cookie cleared.
func (h *AuthHandler) Logout(c *gin.Context) {
	raw, _ := h.readRefreshToken(c)
	_ = h.auth.Logout(c.Request.Context(), raw)
	h.clearRefreshCookie(c)
	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) LogoutAll(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	userID, ok := middleware.UserIDFromContext(c)
	if !ok {
		apiresp.Respond(c, apperr.ErrUnauthorized, requestID)
		return
	}
	if err := h.auth.LogoutAll(c.Request.Context(), userID); err != nil {
		// Still clear the cookie — this browser's token is dead regardless
		// of a DB write failure.
		h.clearRefreshCookie(c)
		apiresp.Respond(c, err, requestID)
		return
	}
	h.clearRefreshCookie(c)
	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) Me(c *gin.Context) {
	requestID := c.GetString(middleware.RequestIDKey)
	userID, ok := middleware.UserIDFromContext(c)
	if !ok {
		apiresp.Respond(c, apperr.ErrUnauthorized, requestID)
		return
	}
	out, err := h.auth.Me(c.Request.Context(), userID)
	if err != nil {
		apiresp.Respond(c, err, requestID)
		return
	}
	c.JSON(http.StatusOK, toMeResponse(out))
}

// ---------- cookie helpers (SRP: transport, one place) ----------

func (h *AuthHandler) setRefreshCookie(c *gin.Context, raw string) {
	maxAge := int(h.authCfg.RefreshTokenTTL.Seconds())
	c.SetSameSite(h.cookieCfg.SameSite)
	c.SetCookie(
		refreshCookieName, raw, maxAge,
		h.cookieCfg.Path, h.cookieCfg.Domain,
		h.cookieCfg.Secure, true, // HttpOnly
	)
}

func (h *AuthHandler) clearRefreshCookie(c *gin.Context) {
	c.SetSameSite(h.cookieCfg.SameSite)
	c.SetCookie(
		refreshCookieName, "", -1,
		h.cookieCfg.Path, h.cookieCfg.Domain,
		h.cookieCfg.Secure, true,
	)
}

// readRefreshToken checks the cookie first (browser path), then a JSON body
// (native client path). fromBody reports which transport supplied the token so
// the caller can answer on the same channel. Returns ("", false) if neither is
// present — the caller decides what to do with that.
func (h *AuthHandler) readRefreshToken(c *gin.Context) (token string, fromBody bool) {
	if v, err := c.Cookie(refreshCookieName); err == nil && v != "" {
		return v, false
	}
	var body dto.RefreshRequest
	if err := c.ShouldBindJSON(&body); err == nil && body.RefreshToken != "" {
		return body.RefreshToken, true
	}
	return "", false
}
