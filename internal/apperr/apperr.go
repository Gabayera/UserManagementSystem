package apperr

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrValidation   = errors.New("validation")
	ErrTimeout = errors.New("timeout")
	ErrUnavailable = errors.New("unavailable")
)

func Wrap(base error, msg string, args ...any) error {
	return fmt.Errorf("%w: %s", base, fmt.Sprintf(msg, args...))
}

// ValidationError is a typed error. errors.Is(err, ErrValidation) must be true.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid %v: %v", e.Field, e.Reason)
}

func (e *ValidationError) Unwrap() error {
	return ErrValidation
}
