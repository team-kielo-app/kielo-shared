package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus/testutil"

	sharedmetrics "github.com/team-kielo-app/kielo-shared/observe/metrics"
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

func TestLegacyAlias_EmitsHeadersAndIncrementsCounter(t *testing.T) {
	sharedmetrics.LegacyAliasHitsTotal.Reset()
	sunset := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	mw := LegacyAlias(LegacyAliasOptions{
		Service:    "mobile-bff",
		Successor:  "/api/v3/me/recommendations/articles",
		SunsetDate: sunset,
	})
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v3/feed", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/api/v3/feed")

	if err := mw(func(c echo.Context) error { return c.NoContent(http.StatusOK) })(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	if got := rec.Header().Get("Deprecation"); got != "true" {
		t.Errorf("Deprecation = %q, want %q", got, "true")
	}
	if got := rec.Header().Get("Sunset"); got != sunset.Format(http.TimeFormat) {
		t.Errorf("Sunset = %q, want %q", got, sunset.Format(http.TimeFormat))
	}
	wantLink := "</api/v3/me/recommendations/articles>; rel=\"successor-version\""
	if got := rec.Header().Get("Link"); got != wantLink {
		t.Errorf("Link = %q, want %q", got, wantLink)
	}

	got := testutil.ToFloat64(sharedmetrics.LegacyAliasHitsTotal.WithLabelValues(
		"mobile-bff", "/api/v3/feed", "/api/v3/me/recommendations/articles"))
	if got != 1 {
		t.Errorf("counter = %v, want 1", got)
	}
}

func TestLegacyAlias_MissingConfigIsNoOp(t *testing.T) {
	// Empty Service / Successor → no-op middleware. Avoids a service
	// panic at boot if a route is wired with the wrong options.
	sharedmetrics.LegacyAliasHitsTotal.Reset()
	mw := LegacyAlias(LegacyAliasOptions{Service: "", Successor: ""})
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v3/feed", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := mw(func(c echo.Context) error { return c.NoContent(http.StatusOK) })(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	if got := rec.Header().Get("Deprecation"); got != "" {
		t.Errorf("misconfigured middleware should be a no-op, got Deprecation=%q", got)
	}
}

func TestLegacyAlias_CounterIncrementsEvenOnHandlerError(t *testing.T) {
	// We want to count every alias hit, not just successful ones —
	// otherwise a backend regression that makes the alias 5xx would
	// hide its usage and let us delete it prematurely.
	sharedmetrics.LegacyAliasHitsTotal.Reset()
	mw := LegacyAlias(LegacyAliasOptions{
		Service:    "mobile-bff",
		Successor:  "/api/v3/me/recommendations/articles",
		SunsetDate: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	})
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v3/feed", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/api/v3/feed")

	_ = mw(func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusInternalServerError, "boom")
	})(c)

	got := testutil.ToFloat64(sharedmetrics.LegacyAliasHitsTotal.WithLabelValues(
		"mobile-bff", "/api/v3/feed", "/api/v3/me/recommendations/articles"))
	if got != 1 {
		t.Errorf("counter = %v, want 1 (alias hits should be counted regardless of handler outcome)", got)
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

func TestDeprecation_MetricIncrementedWhenServiceProvided(t *testing.T) {
	sharedmetrics.V1RouteHitsTotal.Reset()
	mw := Deprecation(DeprecationOptions{Service: "test-service"})

	e := echo.New()
	e.GET("/api/v1/things/:id", func(c echo.Context) error {
		return mw(func(c echo.Context) error {
			return c.NoContent(http.StatusNoContent)
		})(c)
	})

	for _, id := range []string{"abc", "def", "abc"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/things/"+id, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
	}

	// The path label MUST be the Echo template, not the resolved URL —
	// otherwise the cardinality scales with the number of UUIDs in
	// flight rather than the number of registered routes.
	got := testutil.ToFloat64(sharedmetrics.V1RouteHitsTotal.WithLabelValues(
		"test-service", "GET", "/api/v1/things/:id",
	))
	if got != 3 {
		t.Errorf("counter for /api/v1/things/:id = %v, want 3", got)
	}
}

func TestDeprecation_MetricNotIncrementedWhenServiceMissing(t *testing.T) {
	// Backwards compatibility: legacy callers passing
	// DeprecationOptions{} get headers but no metric (avoids polluting
	// the counter with empty-service rows). Once every group declares
	// a Service this branch can be tightened to a hard error.
	sharedmetrics.V1RouteHitsTotal.Reset()
	mw := Deprecation(DeprecationOptions{}) // no Service

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/silent", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if err := mw(func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}

	got := testutil.ToFloat64(sharedmetrics.V1RouteHitsTotal.WithLabelValues(
		"", "GET", "/api/v1/silent",
	))
	if got != 0 {
		t.Errorf("counter for empty service = %v, want 0", got)
	}
}

func TestDeprecation_MetricIncrementedEvenOnHandlerError(t *testing.T) {
	// A v1 route that 4xx/5xx out is still a hit — we want to track
	// "was this URL reached at all", regardless of outcome.
	sharedmetrics.V1RouteHitsTotal.Reset()
	mw := Deprecation(DeprecationOptions{Service: "errs"})

	e := echo.New()
	e.GET("/api/v1/will-fail", func(c echo.Context) error {
		return mw(func(c echo.Context) error {
			return echo.NewHTTPError(http.StatusBadRequest, "nope")
		})(c)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/will-fail", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	got := testutil.ToFloat64(sharedmetrics.V1RouteHitsTotal.WithLabelValues(
		"errs", "GET", "/api/v1/will-fail",
	))
	if got != 1 {
		t.Errorf("counter on 4xx response = %v, want 1", got)
	}
}

func TestDeprecation_MetricSuppressedBySkip(t *testing.T) {
	sharedmetrics.V1RouteHitsTotal.Reset()
	mw := Deprecation(DeprecationOptions{
		Service: "skipper",
		Skip: func(c echo.Context) bool {
			return strings.HasPrefix(c.Request().URL.Path, "/api/v1/events/")
		},
	})

	e := echo.New()
	e.POST("/api/v1/events/behavioral", func(c echo.Context) error {
		return mw(func(c echo.Context) error {
			return c.NoContent(http.StatusNoContent)
		})(c)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/events/behavioral", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	got := testutil.ToFloat64(sharedmetrics.V1RouteHitsTotal.WithLabelValues(
		"skipper", "POST", "/api/v1/events/behavioral",
	))
	if got != 0 {
		t.Errorf("counter for skipped path = %v, want 0", got)
	}
	// And the headers should be suppressed too (Skip is one switch, not
	// two): otherwise we'd be telling clients about a non-existent
	// successor on routes that genuinely have no v3 mirror.
	if dep := rec.Header().Get("Deprecation"); dep != "" {
		t.Errorf("Deprecation header = %q, want empty (Skip should suppress headers)", dep)
	}
}
