package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

func TestDeprecation_DefaultSunsetIs90Days(t *testing.T) {
	mw := Deprecation(DeprecationOptions{})
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := mw(func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})
	if err := handler(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if got := rec.Header().Get("Deprecation"); got != "true" {
		t.Errorf("Deprecation header = %q, want %q", got, "true")
	}
	sunset := rec.Header().Get("Sunset")
	if sunset == "" {
		t.Fatal("Sunset header missing")
	}
	parsed, err := http.ParseTime(sunset)
	if err != nil {
		t.Fatalf("Sunset is not a valid HTTP-date (%q): %v", sunset, err)
	}
	delta := time.Until(parsed)
	if delta < 89*24*time.Hour || delta > 91*24*time.Hour {
		t.Errorf("default sunset should be ~90 days out, got %v", delta)
	}
}

func TestDeprecation_LinkDerivedFromRequestPath(t *testing.T) {
	mw := Deprecation(DeprecationOptions{})
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications/unread-count", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := mw(func(c echo.Context) error { return c.NoContent(http.StatusOK) })(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	link := rec.Header().Get("Link")
	want := "</api/v3/me/notifications/unread-count>; rel=\"successor-version\""
	if link != want {
		t.Errorf("Link header = %q, want %q", link, want)
	}
}

func TestDeprecation_SuccessorPathOverride(t *testing.T) {
	// /klearn/topic-lists → /topic-lists is one of the path renames
	// that needs an explicit override (the default substitution would
	// produce /api/v3/klearn/topic-lists, which doesn't exist).
	mw := Deprecation(DeprecationOptions{SuccessorPath: "/api/v3/topic-lists"})
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/klearn/topic-lists", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := mw(func(c echo.Context) error { return c.NoContent(http.StatusOK) })(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	link := rec.Header().Get("Link")
	if !strings.Contains(link, "</api/v3/topic-lists>") {
		t.Errorf("Link should use override path, got %q", link)
	}
}

func TestDeprecation_FixedSunsetDate(t *testing.T) {
	fixed := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	mw := Deprecation(DeprecationOptions{SunsetDate: fixed})
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := mw(func(c echo.Context) error { return c.NoContent(http.StatusOK) })(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	want := fixed.Format(http.TimeFormat)
	if got := rec.Header().Get("Sunset"); got != want {
		t.Errorf("Sunset = %q, want %q", got, want)
	}
}

func TestDeprecation_SkipFunctionExemptsRoute(t *testing.T) {
	mw := Deprecation(DeprecationOptions{
		Skip: func(c echo.Context) bool {
			return c.Path() == "/api/v1/events/behavioral"
		},
	})
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events/behavioral", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/api/v1/events/behavioral")

	if err := mw(func(c echo.Context) error { return c.NoContent(http.StatusOK) })(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if got := rec.Header().Get("Deprecation"); got != "" {
		t.Errorf("Skip should suppress Deprecation header, got %q", got)
	}
	if got := rec.Header().Get("Sunset"); got != "" {
		t.Errorf("Skip should suppress Sunset header, got %q", got)
	}
}

func TestDeprecation_HeadersWrittenBeforeFlush(t *testing.T) {
	// SSE handlers Flush early; the deprecation headers must already
	// be on the response writer when that happens. Smoke this by
	// having the inner handler Flush after WriteHeader and asserting
	// the headers are visible on the recorder.
	mw := Deprecation(DeprecationOptions{})
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications/stream", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := mw(func(c echo.Context) error {
		c.Response().WriteHeader(http.StatusOK)
		if flusher, ok := c.Response().Writer.(http.Flusher); ok {
			flusher.Flush()
		}
		_, _ = c.Response().Write([]byte("event: ping\n\n"))
		return nil
	})(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if rec.Header().Get("Deprecation") != "true" {
		t.Error("Deprecation header missing on streaming response")
	}
	if rec.Header().Get("Sunset") == "" {
		t.Error("Sunset header missing on streaming response")
	}
}
