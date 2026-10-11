package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockOnContext stands in for a query on a stalled connection: it returns
// only when the request context ends, as pgx does.
func blockOnContext(c echo.Context) error {
	<-c.Request().Context().Done()
	return c.Request().Context().Err()
}

func serveWithDeadline(t *testing.T, cfg RequestDeadlineConfig, h echo.HandlerFunc, req *http.Request) (*httptest.ResponseRecorder, time.Duration) {
	t.Helper()
	e := echo.New()
	e.Use(RequestDeadline(cfg))
	e.Any("/*", h)
	rec := httptest.NewRecorder()
	start := time.Now()
	e.ServeHTTP(rec, req)
	return rec, time.Since(start)
}

func TestRequestDeadlineFailsAStalledRequestWith503(t *testing.T) {
	rec, took := serveWithDeadline(t, RequestDeadlineConfig{Default: 50 * time.Millisecond}, blockOnContext,
		httptest.NewRequest(http.MethodGet, "/internal/api/v3/users/x/exists", nil))

	assert.Less(t, took, time.Second)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "SERVICE_UNAVAILABLE", body.Error.Code)
}

func TestRequestDeadlineLongestPrefixWins(t *testing.T) {
	cfg := RequestDeadlineConfig{
		Default: 20 * time.Millisecond,
		Routes: []RouteDeadline{
			{Prefix: "/internal/", Timeout: 40 * time.Millisecond},
			{Prefix: "/internal/pubsub/", Timeout: 300 * time.Millisecond},
		},
	}
	for path, want := range map[string]time.Duration{
		"/api/v3/me/progress":             20 * time.Millisecond,
		"/internal/api/v3/users/x/exists": 40 * time.Millisecond,
		"/internal/pubsub/process-outbox": 300 * time.Millisecond,
	} {
		_, took := serveWithDeadline(t, cfg, blockOnContext, httptest.NewRequest(http.MethodPost, path, nil))
		assert.GreaterOrEqual(t, took, want, path)
		assert.Less(t, took, want+200*time.Millisecond, path)
	}
}

func TestRequestDeadlineLeavesStreamsAndOptOutsAlone(t *testing.T) {
	cfg := RequestDeadlineConfig{
		Default: 20 * time.Millisecond,
		Routes:  []RouteDeadline{{Prefix: "/api/v3/me/notifications/stream", Timeout: 0}},
	}
	noDeadline := func(c echo.Context) error {
		_, ok := c.Request().Context().Deadline()
		assert.False(t, ok, c.Request().URL.Path)
		return c.NoContent(http.StatusOK)
	}

	sse := httptest.NewRequest(http.MethodGet, "/api/v3/me/anything", nil)
	sse.Header.Set("Accept", "text/event-stream")
	ws := httptest.NewRequest(http.MethodGet, "/websockify", nil)
	ws.Header.Set("Upgrade", "websocket")
	optOut := httptest.NewRequest(http.MethodGet, "/api/v3/me/notifications/stream", nil)

	for _, req := range []*http.Request{sse, ws, optOut} {
		rec, _ := serveWithDeadline(t, cfg, noDeadline, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestRequestDeadlineDoesNotTouchFastOrStartedResponses(t *testing.T) {
	cfg := RequestDeadlineConfig{Default: 30 * time.Millisecond}

	rec, _ := serveWithDeadline(t, cfg, func(c echo.Context) error { return c.String(http.StatusOK, "ok") },
		httptest.NewRequest(http.MethodGet, "/fast", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("Retry-After"))

	rec, _ = serveWithDeadline(t, cfg, func(c echo.Context) error {
		c.Response().WriteHeader(http.StatusOK)
		return blockOnContext(c)
	}, httptest.NewRequest(http.MethodGet, "/started", nil))
	assert.Equal(t, http.StatusOK, rec.Code, "a response already on the wire keeps its status")
}
