package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBadRequestSignature_RejectsObjectLiteralPath(t *testing.T) {
	e := echo.New()
	e.Use(BadRequestSignature())
	handlerCalled := false
	e.GET("/conversations/scenarios/:id", func(c echo.Context) error {
		handlerCalled = true
		return c.String(http.StatusOK, "ok")
	})

	// Use the URL-encoded form for the request line (the only form a
	// real HTTP request can carry — Go's httptest.NewRequest panics
	// on unencoded `[` or space in the request line). Go's net/url
	// decodes `%5B`→`[` and `%20`→` ` into URL.Path before the
	// middleware sees it. Both the URL-encoded and pre-decoded
	// representations land on the same Path string, so we only need
	// to exercise the encoded one to cover both wire shapes.
	cases := []struct {
		name string
		path string
	}{
		{"url-encoded object Object", "/conversations/scenarios/%5Bobject%20Object%5D"},
		{"mid-segment", "/something/%5Bobject/whatever"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handlerCalled = false
			req := httptest.NewRequest(http.MethodGet, tc.path, http.NoBody)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.False(t, handlerCalled, "downstream handler must not run")
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, "BAD_REQUEST_SIGNATURE", body.Error.Code)
		})
	}
}

func TestBadRequestSignature_PassesThroughCleanPaths(t *testing.T) {
	e := echo.New()
	e.Use(BadRequestSignature())
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	e.GET("/conversations/scenarios/:id", func(c echo.Context) error {
		return c.String(http.StatusOK, c.Param("id"))
	})

	cases := []string{
		"/healthz",
		"/conversations/scenarios/abc-123",
		"/conversations/scenarios/object",       // 'object' alone is fine
		"/conversations/scenarios/object-store", // common legitimate slug
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code, "path %s should pass through", path)
		})
	}
}
