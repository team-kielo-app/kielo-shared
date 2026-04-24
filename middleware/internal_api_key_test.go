package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// Tests for the shared internal-API-key middleware, used by every
// service-to-service boundary (mobile-bff → content-service, learn
// engine → comms, etc.). This is security-critical: a silent
// regression could either let an unauthenticated caller through the
// fence or lock out a correctly-configured peer with a 500.
//
// The middleware has two variants (Echo and net/http) that must
// behave identically. Both are covered below.

const testKey = "shared-secret-123"

func echoHandlerReturningOK(c echo.Context) error {
	return c.String(http.StatusOK, "allowed")
}

func netHTTPHandlerReturningOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("allowed"))
	})
}

// --- Echo middleware ---

func TestEcho_AllowsRequestWithCorrectKey(t *testing.T) {
	e := echo.New()
	e.Use(InternalAPIKeyAuth(NewInternalAPIKeyConfig(testKey)))
	e.GET("/private", echoHandlerReturningOK)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(InternalAPIKeyHeader, testKey)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "allowed", rec.Body.String())
}

func TestEcho_RejectsRequestWithMissingHeader(t *testing.T) {
	// Expected key is set (peer is authenticated path) but the
	// header is missing → 401, not 500. 500 is reserved for
	// server-side misconfig (expectedKey unset), not for caller
	// errors.
	e := echo.New()
	e.Use(InternalAPIKeyAuth(NewInternalAPIKeyConfig(testKey)))
	e.GET("/private", echoHandlerReturningOK)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestEcho_RejectsRequestWithWrongKey(t *testing.T) {
	e := echo.New()
	e.Use(InternalAPIKeyAuth(NewInternalAPIKeyConfig(testKey)))
	e.GET("/private", echoHandlerReturningOK)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(InternalAPIKeyHeader, "wrong-key")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestEcho_TrimsWhitespaceOnProvidedKey(t *testing.T) {
	// Whitespace-only header is treated as missing (not as an
	// invalid key) — callers may send " " from a misconfigured
	// template and we want the "missing" error message, not
	// "invalid", since that's more diagnosable.
	e := echo.New()
	e.Use(InternalAPIKeyAuth(NewInternalAPIKeyConfig(testKey)))
	e.GET("/private", echoHandlerReturningOK)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(InternalAPIKeyHeader, "   ")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "missing", "whitespace-only header should route to missing, not invalid")
}

func TestEcho_TrimsWhitespaceOnExpectedKey(t *testing.T) {
	// An expectedKey with trailing whitespace from an env var must
	// match a correctly-configured peer's key WITHOUT that
	// whitespace. Otherwise every internal call fails whenever a
	// .env file gains a trailing newline.
	cfg := NewInternalAPIKeyConfig("  " + testKey + "  ")
	e := echo.New()
	e.Use(InternalAPIKeyAuth(cfg))
	e.GET("/private", echoHandlerReturningOK)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(InternalAPIKeyHeader, testKey)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEcho_ReturnsMisconfigErrorWhenKeyUnset(t *testing.T) {
	// Server started without an expected key configured → every
	// call fails closed with 500. This is intentional fail-secure:
	// a silent pass-through would open the internal surface area.
	e := echo.New()
	e.Use(InternalAPIKeyAuth(NewInternalAPIKeyConfig("")))
	e.GET("/private", echoHandlerReturningOK)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(InternalAPIKeyHeader, "anything")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "not configured")
}

func TestEcho_AllowMissingExpectedEnablesDevPassThrough(t *testing.T) {
	// The explicit dev/test escape hatch: expectedKey="" AND
	// AllowMissingExpected=true. This is how local dev without
	// KIELO_INTERNAL_API_KEY set can still make calls work.
	cfg := NewInternalAPIKeyConfig("")
	cfg.AllowMissingExpected = true
	e := echo.New()
	e.Use(InternalAPIKeyAuth(cfg))
	e.GET("/private", echoHandlerReturningOK)

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEcho_AllowPathsBypassesAuth(t *testing.T) {
	// Specific full-path exact matches (e.g. "/healthz", "/metrics")
	// are always allowed, even without a key. Critical for k8s
	// liveness / Cloud Run startup probes that can't sign requests.
	cfg := NewInternalAPIKeyConfig(testKey)
	cfg.AllowPaths = []string{"/healthz", "/readyz"}
	e := echo.New()
	e.Use(InternalAPIKeyAuth(cfg))
	e.GET("/healthz", echoHandlerReturningOK)
	e.GET("/private", echoHandlerReturningOK)

	// Allowed path: no header → 200.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Non-allowed path: still 401.
	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestEcho_AllowPathPrefixesBypassesAuth(t *testing.T) {
	// Prefix-match version: "/pubsub/" covers every subscription
	// push handler without having to enumerate each one.
	cfg := NewInternalAPIKeyConfig(testKey)
	cfg.AllowPathPrefixes = []string{"/pubsub/"}
	e := echo.New()
	e.Use(InternalAPIKeyAuth(cfg))
	e.GET("/pubsub/any-topic", echoHandlerReturningOK)
	e.GET("/pubsub-not-this", echoHandlerReturningOK)

	req := httptest.NewRequest(http.MethodGet, "/pubsub/any-topic", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// "/pubsub-not-this" doesn't start with "/pubsub/" (note the slash).
	// Must NOT match the prefix — prefixes are literal, not glob.
	req = httptest.NewRequest(http.MethodGet, "/pubsub-not-this", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestEcho_CustomHeaderNameRespected(t *testing.T) {
	// Some services needed to rename the header (e.g. during migrations).
	// The cfg.HeaderName override must take effect without falling
	// back to the default X-Internal-API-Key.
	cfg := NewInternalAPIKeyConfig(testKey)
	cfg.HeaderName = "X-Service-Token"
	e := echo.New()
	e.Use(InternalAPIKeyAuth(cfg))
	e.GET("/private", echoHandlerReturningOK)

	// Wrong header name → still 401.
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(InternalAPIKeyHeader, testKey) // old default
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Correct custom header → 200.
	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set("X-Service-Token", testKey)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- net/http middleware (must behave identically to Echo variant) ---

func TestNetHTTP_AllowsWithCorrectKey(t *testing.T) {
	wrapped := InternalAPIKeyMiddleware(NewInternalAPIKeyConfig(testKey))(netHTTPHandlerReturningOK())
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(InternalAPIKeyHeader, testKey)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	assert.Equal(t, "allowed", string(body))
}

func TestNetHTTP_RejectsMissingKey(t *testing.T) {
	wrapped := InternalAPIKeyMiddleware(NewInternalAPIKeyConfig(testKey))(netHTTPHandlerReturningOK())
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestNetHTTP_RejectsWrongKey(t *testing.T) {
	wrapped := InternalAPIKeyMiddleware(NewInternalAPIKeyConfig(testKey))(netHTTPHandlerReturningOK())
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(InternalAPIKeyHeader, "wrong")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestNetHTTP_ReturnsMisconfigWhenKeyUnset(t *testing.T) {
	wrapped := InternalAPIKeyMiddleware(NewInternalAPIKeyConfig(""))(netHTTPHandlerReturningOK())
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(InternalAPIKeyHeader, "anything")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestNetHTTP_AllowPathsBypasses(t *testing.T) {
	cfg := NewInternalAPIKeyConfig(testKey)
	cfg.AllowPaths = []string{"/healthz"}
	wrapped := InternalAPIKeyMiddleware(cfg)(netHTTPHandlerReturningOK())

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	req = httptest.NewRequest(http.MethodGet, "/private", nil)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
