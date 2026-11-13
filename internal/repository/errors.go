package repository

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"UserManagementSystem/internal/apperr"
)

// MapError translates a pgx / pgconn error into an apperr sentinel (wrapped
// so errors.Is works) or a wrapped raw error if the SQLSTATE isn't mapped.
// Every repository method must call MapError on every non-nil error path.
func MapError(err error) error {
	if err == nil {
		return nil
	}

	// pgx v5 has carried ErrNoRows across several internal representations
	// over time (a bare sentinel in older versions, a *proxyErr wrapper in
	// newer ones whose Is() compares two independently-constructed inner
	// errors and can return false across instances). Match both errors.Is
	// and the stable error text.
	if errors.Is(err, pgx.ErrNoRows) || err.Error() == pgx.ErrNoRows.Error() {
		return apperr.ErrNotFound
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", apperr.ErrTimeout, err)
	}
	if errors.Is(err, context.Canceled) {
		// Caller cancelled — let the handler decide what to do.
		return err
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return mapSQLState(pgErr)
	}

	// Unrecognized error — wrap, no sentinel. Becomes 500 at the HTTP layer.
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
