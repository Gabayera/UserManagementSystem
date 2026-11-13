package security

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTIssuer signs and verifies HS256 access tokens.
type JWTIssuer struct {
	secret []byte
	issuer string
	ttl    time.Duration
}

// Claims is the access-token payload. No roles/permissions (ADR-003) — RBAC
// is resolved per request.
type Claims struct {
	jwt.RegisteredClaims
	Typ string `json:"typ"`
}

func NewJWTIssuer(secret []byte, issuer string, ttl time.Duration) *JWTIssuer {
	return &JWTIssuer{secret: secret, issuer: issuer, ttl: ttl}
}

// Sign returns the token, its jti, and the exact expiry timestamp.
func (j *JWTIssuer) Sign(userID uuid.UUID) (string, uuid.UUID, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(j.ttl)
	jti := uuid.New()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        jti.String(),
		},
		Typ: "access",
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(j.secret)
	if err != nil {
		return "", uuid.Nil, time.Time{}, fmt.Errorf("%w: sign: %v", ErrTokenInvalid, err)
	}
	return tok, jti, exp, nil
}

// Verify parses and validates the token. Enforces alg=HS256, iss, exp, iat,
// typ=access, and a UUID-parsable sub. On failure the returned error wraps
// either ErrTokenExpired or ErrTokenInvalid so callers can errors.Is them.
func (j *JWTIssuer) Verify(raw string) (*Claims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(j.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
	)
	var claims Claims
	tok, err := parser.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		return j.secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: %v", ErrTokenExpired, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if !tok.Valid {
		return nil, fmt.Errorf("%w: token not valid", ErrTokenInvalid)
	}
	if claims.Typ != "access" {
		return nil, fmt.Errorf("%w: unexpected token type", ErrTokenInvalid)
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		return nil, fmt.Errorf("%w: subject is not a uuid", ErrTokenInvalid)
	}
	return &claims, nil
}
