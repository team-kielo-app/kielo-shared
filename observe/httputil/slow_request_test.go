package httputil

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	fn()
	return buf.String()
}

func runSlowReq(t *testing.T, mw echo.MiddlewareFunc, path string, handler echo.HandlerFunc) (status int, logLine string) {
	t.Helper()
	e := echo.New()
	e.Use(mw)
	e.GET(path, handler)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	out := captureLog(t, func() {
		e.ServeHTTP(rec, req)
	})
	return rec.Code, out
}

func TestSlowRequest_FastBypassesLogging(t *testing.T) {
	status, logged := runSlowReq(
		t,
		SlowRequestLogger(SlowRequestOptions{Threshold: 100 * time.Millisecond}),
		"/api/v3/me/profile",
		func(c echo.Context) error { return c.String(http.StatusOK, "ok") },
	)
	if status != http.StatusOK {
		t.Fatalf("want 200, got %d", status)
	}
	if strings.Contains(logged, "[slow]") {
		t.Errorf("fast handler should not log; got %q", logged)
	}
}

func TestSlowRequest_OverBudgetLogs(t *testing.T) {
	status, logged := runSlowReq(
		t,
		SlowRequestLogger(SlowRequestOptions{Threshold: 50 * time.Millisecond}),
		"/api/v3/feed",
		func(c echo.Context) error {
			time.Sleep(120 * time.Millisecond)
			return c.JSON(http.StatusOK, map[string]string{"ok": "1"})
		},
	)
	if status != http.StatusOK {
		t.Fatalf("want 200, got %d", status)
	}
	if !strings.Contains(logged, "[slow]") {
		t.Fatalf("over-budget handler should log; got %q", logged)
	}
	if !strings.Contains(logged, "GET /api/v3/feed") {
		t.Errorf("log should include method+path; got %q", logged)
	}
	if !strings.Contains(logged, "budget=50ms") {
		t.Errorf("log should include budget; got %q", logged)
	}
	if !strings.Contains(logged, "status=200") {
		t.Errorf("log should include status; got %q", logged)
	}
}

func TestSlowRequest_HealthProbesSkippedByDefault(t *testing.T) {
	for _, path := range []string{
		"/health",
		"/readyz",
		"/metrics",
		"/health/ready",
		// SSE / streaming endpoints — by convention any path ending in
		// `/stream` is intentionally long-lived and should not log slow.
		"/api/v1/me/notifications/stream",
		"/api/v3/me/notifications/stream",
		"/api/v3/concept-hubs/generation/abc/stream",
		"/api/v3/conversations/sessions/abc/transcript/live/stream",
		"/api/v3/tts/paragraphs/jobs/abc/stream",
	} {
		_, logged := runSlowReq(
			t,
			SlowRequestLogger(SlowRequestOptions{Threshold: 5 * time.Millisecond}),
			path,
			func(c echo.Context) error {
				time.Sleep(20 * time.Millisecond)
				return c.NoContent(http.StatusOK)
			},
		)
		if strings.Contains(logged, "[slow]") {
			t.Errorf("path %s should be skipped by default; got %q", path, logged)
		}
	}
}

func TestSlowRequest_CustomSkipOverridesDefault(t *testing.T) {
	mw := SlowRequestLogger(SlowRequestOptions{
		Threshold: 5 * time.Millisecond,
		Skip:      func(c echo.Context) bool { return false }, // skip nothing
	})
	_, logged := runSlowReq(t, mw, "/health", func(c echo.Context) error {
		time.Sleep(20 * time.Millisecond)
		return c.NoContent(http.StatusOK)
	})
	if !strings.Contains(logged, "[slow]") {
		t.Errorf("custom Skip=false should let /health log; got %q", logged)
	}
}

func TestSlowRequest_DefaultThresholdIs1s(t *testing.T) {
	// 500ms handler under default 1s threshold should NOT log.
	_, logged := runSlowReq(
		t,
		SlowRequestLogger(SlowRequestOptions{}),
		"/api/v3/feed",
		func(c echo.Context) error {
			time.Sleep(50 * time.Millisecond)
			return c.NoContent(http.StatusOK)
		},
	)
	if strings.Contains(logged, "[slow]") {
		t.Errorf("default threshold should be 1s; 50ms should not log; got %q", logged)
	}
}
