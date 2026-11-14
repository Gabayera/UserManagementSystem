package apiresp

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"UserManagementSystem/internal/apperr"
	"UserManagementSystem/internal/dto"
)

// Respond is the single choke point that maps any error to an HTTP response.
// Handlers and middleware call it; nothing else writes an error envelope.
// 5xx bodies are always generic ("internal error") — never leak err.Error().
func Respond(c *gin.Context, err error, requestID string) {
	status, code := statusFor(err)
	logError(status, code, err, requestID)
	c.JSON(status, dto.ErrorEnvelope{
		Error: dto.ErrorBody{Code: code, Message: messageFor(status, code)},
	})
}

// RespondValidation is the special-case helper for ShouldBindJSON failures.
// Body is always the same — the raw validator string is never echoed.
func RespondValidation(c *gin.Context, requestID string) {
	slog.Warn("handler_validation_error", "request_id", requestID)
	c.JSON(http.StatusUnprocessableEntity, dto.ErrorEnvelope{
		Error: dto.ErrorBody{Code: dto.CodeInvalidInput, Message: "invalid input"},
	})
}

func statusFor(err error) (int, string) {
	switch {
	case errors.Is(err, apperr.ErrNotFound):
		return http.StatusNotFound, dto.CodeNotFound
	case errors.Is(err, apperr.ErrConflict):
		return http.StatusConflict, dto.CodeConflict
	case errors.Is(err, apperr.ErrValidation):
		return http.StatusUnprocessableEntity, dto.CodeValidation
	case errors.Is(err, apperr.ErrUnauthorized):
		return http.StatusUnauthorized, dto.CodeUnauthorized
	case errors.Is(err, apperr.ErrForbidden):
		return http.StatusForbidden, dto.CodeForbidden
	case errors.Is(err, apperr.ErrTimeout):
		return http.StatusGatewayTimeout, dto.CodeTimeout
	case errors.Is(err, apperr.ErrUnavailable):
		return http.StatusServiceUnavailable, dto.CodeUnavailable
	default:
		return http.StatusInternalServerError, dto.CodeInternal
	}
}

func messageFor(status int, code string) string {
	switch status {
	case http.StatusInternalServerError:
		return "internal error"
	case http.StatusGatewayTimeout:
		return "gateway timeout"
	case http.StatusServiceUnavailable:
		return "service unavailable"
	}
	return code
}

func logError(status int, code string, err error, requestID string) {
	if status >= 500 {
		// Full error including wrapped pgx details — server-side only.
		slog.Error("handler_error",
			"request_id", requestID,
			"status", status, "code", code, "err", err)
		return
	}
	// 4xx: log code + status only. Do NOT log err — client-controlled text
	// can poison logs, and constraint names from repositories are the only
	// value at this level (which shows up as "code=conflict" anyway).
	slog.Warn("handler_client_error",
		"request_id", requestID,
		"status", status, "code", code)
}
