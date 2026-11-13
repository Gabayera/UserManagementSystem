package security

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenInvalid       = errors.New("token invalid")
	ErrPasswordHashFailed = errors.New("password hash failed")
)
