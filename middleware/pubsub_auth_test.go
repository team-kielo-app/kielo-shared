package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func newRequestWithAuth(authHeader string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/internal/pubsub", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func TestPubSubAuth_SkipBypassesEverything(t *testing.T) {
	called := false
	mw := PubSubAuth(PubSubAuthConfig{Audience: "https://example.test/x", Skip: true})
	handler := mw(func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusOK)
	})

	c, rec := newRequestWithAuth("")
	if err := handler(c); err != nil {
		t.Fatalf("handler returned err: %v", err)
	}
	assert.True(t, called, "handler should run when Skip is true")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPubSubAuth_MissingAuthorizationReturns401(t *testing.T) {
	mw := PubSubAuth(PubSubAuthConfig{Audience: "https://example.test/x"})
	handler := mw(func(c echo.Context) error {
		t.Fatalf("handler must not run when authorization is missing")
		return nil
	})

	c, _ := newRequestWithAuth("")
	err := handler(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected echo.HTTPError, got %T (%v)", err, err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestPubSubAuth_NonBearerPrefixReturns401(t *testing.T) {
	mw := PubSubAuth(PubSubAuthConfig{Audience: "https://example.test/x"})
	handler := mw(func(c echo.Context) error {
		t.Fatalf("handler must not run for non-Bearer auth")
		return nil
	})

	c, _ := newRequestWithAuth("Basic abc123")
	err := handler(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected echo.HTTPError, got %T (%v)", err, err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestPubSubAuth_EmptyBearerTokenReturns401(t *testing.T) {
	// "Bearer " with nothing after must be rejected — otherwise we'd
	// pass an empty string to the Google validator which produces a
	// less-clear error.
	mw := PubSubAuth(PubSubAuthConfig{Audience: "https://example.test/x"})
	handler := mw(func(c echo.Context) error {
		t.Fatalf("handler must not run for empty bearer token")
		return nil
	})

	c, _ := newRequestWithAuth("Bearer ")
	err := handler(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected echo.HTTPError, got %T (%v)", err, err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}

func TestPubSubAuth_GarbageTokenReturns401(t *testing.T) {
	// A well-formed-looking but invalid JWT must be rejected by the
	// Google validator. We can't easily mock idtoken.NewValidator, so
	// we just confirm the middleware reaches the validator and bubbles
	// up its error as 401 (rather than 500).
	mw := PubSubAuth(PubSubAuthConfig{Audience: "https://example.test/x"})
	handler := mw(func(c echo.Context) error {
		t.Fatalf("handler must not run for invalid token")
		return nil
	})

	c, _ := newRequestWithAuth("Bearer not.a.real.token")
	err := handler(c)
	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected echo.HTTPError, got %T (%v)", err, err)
	}
	assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
}
