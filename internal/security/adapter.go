package security

import "github.com/google/uuid"

// JWTVerifierAdapter adapts JWTIssuer to the narrow shape expected by
// middleware.Auth. Placed here (in security) rather than in middleware so
// the middleware package stays free of imports from security — DIP at the
// seam.
type JWTVerifierAdapter struct {
	Issuer *JWTIssuer
}

func (a JWTVerifierAdapter) Verify(raw string) (uuid.UUID, uuid.UUID, error) {
	claims, err := a.Issuer.Verify(raw)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	jti, err := uuid.Parse(claims.ID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return userID, jti, nil
}
