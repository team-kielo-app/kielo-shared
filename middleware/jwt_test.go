package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestFlexibleAuth_HeaderTrustRequiresInternalKey(t *testing.T) {
	t.Setenv("KIELO_INTERNAL_API_KEY", "test-internal-key")

	e := echo.New()
	mw := FlexibleAuth("", nil)

	t.Run("rejects header trust without internal key", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.Header.Set("X-User-ID", "00000000-0000-0000-0000-000000000001")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := mw(func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})(c)

		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		httpErr, ok := err.(*echo.HTTPError)
		if !ok {
			t.Fatalf("expected HTTPError, got %T", err)
		}
		if httpErr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", httpErr.Code)
		}
	})

	t.Run("accepts header trust with internal key", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.Header.Set("X-User-ID", "00000000-0000-0000-0000-000000000002")
		req.Header.Set("X-Internal-API-Key", "test-internal-key")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		called := false
		err := mw(func(c echo.Context) error {
			called = true
			return c.NoContent(http.StatusOK)
		})(c)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !called {
			t.Fatalf("expected handler to be called")
		}
	})
}

// TestJWTAuth_IgnoresForgedApiGatewayUserInfoHeader guards the S4 fix: the
// x-apigateway-api-userinfo header must NEVER be trusted — even with a valid
// internal API key — because nothing legitimately sets it and it carried an
// unsigned role claim (the admin-impersonation vector). Identity must come
// only from a signature-verified JWT.
func TestJWTAuth_IgnoresForgedApiGatewayUserInfoHeader(t *testing.T) {
	t.Setenv("KIELO_INTERNAL_API_KEY", "test-internal-key")

	e := echo.New()
	mw := JWTAuthWithOptions("", nil, nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Header.Set("x-apigateway-api-userinfo", `{"user_id":"00000000-0000-0000-0000-000000000009","role":"admin"}`)
	req.Header.Set("X-Internal-API-Key", "test-internal-key")
	// No Authorization: Bearer — a verified JWT is now the only accepted
	// identity source, so this forged request must be rejected.
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	called := false
	err := mw(func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusOK)
	})(c)

	if called {
		t.Fatalf("handler ran — the forged x-apigateway-api-userinfo header was trusted (S4 regression)")
	}
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected HTTPError, got %T (%v)", err, err)
	}
	if httpErr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", httpErr.Code)
	}
}
