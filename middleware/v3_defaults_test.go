package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestMountV3Defaults_AppliesEnvelopeAndCacheControl(t *testing.T) {
	e := echo.New()
	g := e.Group("/api/v3")
	MountV3Defaults(g)
	g.GET("/thing", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"hello": "world"})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v3/thing", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Errorf("Cache-Control = %q, want %q (PrivateNoStore not mounted?)", got, "private, no-store")
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	data, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("response body not wrapped in {data:...} envelope: %s", rec.Body.String())
	}
	if data["hello"] != "world" {
		t.Errorf("inner payload not preserved: %v", data)
	}
}

func TestMountV3Defaults_CacheOverrideRespected(t *testing.T) {
	e := echo.New()
	g := e.Group("/api/v3")
	MountV3Defaults(g)
	g.GET("/cached", func(c echo.Context) error {
		c.Response().Header().Set("Cache-Control", "public, max-age=60")
		return c.JSON(http.StatusOK, map[string]string{"x": "y"})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v3/cached", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=60" {
		t.Errorf("handler override should win; got %q", got)
	}
}
