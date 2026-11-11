package repository

import (
	"UserManagementSystem/internal/apperr"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgconn"
)

func MapError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", apperr.ErrTimeout, err)
	}

	if errors.Is(err, context.Canceled) {
		return err
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return mapSQLState(pgErr)
	}

	return fmt.Errorf("repository: %w", err)
}

func mapSQLState(pgErr *pgconn.PgError) error {
	switch pgErr.Code {
	case "23505": // unique_violation
		return fmt.Errorf("%w: %s", apperr.ErrConflict, pgErr.ConstraintName)
	case "23503": // foreign_key_violation — treated as validation (see Part 6 §1.3)
		return fmt.Errorf("%w: %s", apperr.ErrValidation, pgErr.ConstraintName)
	case "23514": // check_violation
		return fmt.Errorf("%w: %s", apperr.ErrValidation, pgErr.ConstraintName)
	case "23502": // not_null_violation — programmer error; log at WARN
		slog.Warn("repository_not_null_violation",
			"constraint", pgErr.ConstraintName,
			"table", pgErr.TableName,
			"detail", pgErr.Detail,
		)
		return fmt.Errorf("%w: not_null", apperr.ErrValidation)
	case "40001": // serialization_failure — retriable
		return fmt.Errorf("%w: serialization_failure", apperr.ErrConflict)
	case "57014": // query_canceled (statement_timeout)
		return fmt.Errorf("%w: query_canceled", apperr.ErrTimeout)
	case "57P01", "57P02", "57P03": // admin_shutdown / crash_shutdown / cannot_connect_now
		return fmt.Errorf("%w: %s", apperr.ErrUnavailable, pgErr.Code)
	case "08000", "08001", "08006": // connection failures
		return fmt.Errorf("%w: %s", apperr.ErrUnavailable, pgErr.Code)
	default:
		slog.Warn("repository_unexpected_pgerror",
			"code", pgErr.Code,
			"message", pgErr.Message,
			"constraint", pgErr.ConstraintName,
		)
		return fmt.Errorf("repository: %w", pgErr)
	}
}
