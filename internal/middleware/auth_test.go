package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"UserManagementSystem/internal/dto"
)

type fakeVerifier struct {
	fn func(raw string) (uuid.UUID, uuid.UUID, error)
}

func (f *fakeVerifier) Verify(raw string) (uuid.UUID, uuid.UUID, error) {
	if f.fn == nil {
		return uuid.Nil, uuid.Nil, errors.New("not configured")
	}
	return f.fn(raw)
}

func newAuthRouter(v TokenVerifier) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestID())
	r.Use(RequestContext())
	r.Use(Auth(v))
	r.GET("/protected", func(c *gin.Context) {
		uid, ok := UserIDFromContext(c)
		if !ok {
			c.JSON(500, gin.H{"error": "user_id missing"})
			return
		}
		c.JSON(200, gin.H{"user_id": uid.String()})
	})
	return r
}

func TestAuth_MissingHeader_Returns401(t *testing.T) {
	v := &fakeVerifier{fn: func(raw string) (uuid.UUID, uuid.UUID, error) {
		t.Fatal("verifier should not be called when header is absent")
		return uuid.Nil, uuid.Nil, nil
	}}
	w := httptest.NewRecorder()
	newAuthRouter(v).ServeHTTP(w, httptest.NewRequest("GET", "/protected", nil))

	if w.Code != 401 {
		t.Fatalf("status=%d want 401", w.Code)
	}
	var env dto.ErrorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Error.Code != dto.CodeUnauthorized {
		t.Fatalf("code=%q want %q", env.Error.Code, dto.CodeUnauthorized)
	}
}

func TestAuth_AllFailuresProduceIdenticalBody(t *testing.T) {
	cases := []struct {
		name   string
		header string
		verr   error
	}{
		{"missing_header", "", nil},
		{"wrong_scheme", "Basic dXNlcjpwYXNz", nil},
		{"no_token", "Bearer ", nil},
		{"expired", "Bearer expired-token", errors.New("token expired")},
		{"bad_signature", "Bearer tampered", errors.New("invalid signature")},
	}

	var bodies [][]byte
	for _, tc := range cases {
		tc := tc
		v := &fakeVerifier{fn: func(raw string) (uuid.UUID, uuid.UUID, error) {
			if tc.verr != nil {
				return uuid.Nil, uuid.Nil, tc.verr
			}
			return uuid.Nil, uuid.Nil, nil
		}}
		req := httptest.NewRequest("GET", "/protected", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		w := httptest.NewRecorder()
		newAuthRouter(v).ServeHTTP(w, req)
		if w.Code != 401 {
			t.Fatalf("%s: status=%d want 401", tc.name, w.Code)
		}
		bodies = append(bodies, w.Body.Bytes())
	}

	for i := 1; i < len(bodies); i++ {
		if !bytes.Equal(bodies[0], bodies[i]) {
			t.Fatalf("case %d body differs from case 0\n  case0=%s\n  case%d=%s",
				i, bodies[0], i, bodies[i])
		}
	}
}

func TestAuth_ValidToken_SetsUserIDInContext(t *testing.T) {
	want := uuid.New()
	jti := uuid.New()
	v := &fakeVerifier{fn: func(raw string) (uuid.UUID, uuid.UUID, error) {
		if raw != "good-token" {
			t.Fatalf("raw=%q", raw)
		}
		return want, jti, nil
	}}
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	w := httptest.NewRecorder()
	newAuthRouter(v).ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d want 200 body=%s", w.Code, w.Body.String())
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.UserID != want.String() {
		t.Fatalf("user_id=%q want %q", body.UserID, want)
	}
}

func TestAuth_CaseInsensitiveBearerScheme(t *testing.T) {
	v := &fakeVerifier{fn: func(raw string) (uuid.UUID, uuid.UUID, error) {
		return uuid.New(), uuid.New(), nil
	}}
	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", scheme+" tok")
		w := httptest.NewRecorder()
		newAuthRouter(v).ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("scheme=%q status=%d", scheme, w.Code)
		}
	}
}
