package middleware

import (
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
		req := httptest.NewRequest(http.MethodGet, "/", nil)
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
		req := httptest.NewRequest(http.MethodGet, "/", nil)
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
