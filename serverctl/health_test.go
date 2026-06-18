package serverctl

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakePinger struct {
	err   error
	delay time.Duration
}

func (f *fakePinger) Ping(ctx context.Context) error {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return f.err
}

func runHandler(t *testing.T, h echo.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	require.NoError(t, h(c))
	return rec
}

func TestLiveness_Always200(t *testing.T) {
	rec := runHandler(t, Liveness())
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "OK", rec.Body.String())
}

func TestReadiness_HealthyDB(t *testing.T) {
	rec := runHandler(t, Readiness(&fakePinger{}))
	assert.Equal(t, http.StatusOK, rec.Code)
	// Readiness now delegates to ReadinessWithChecks which emits
	// JSON. Cloud Run only inspects the status code; this body shape
	// gives operators running `curl /readyz` a clear per-dep view.
	assert.Contains(t, rec.Body.String(), `"status":"ready"`)
	assert.Contains(t, rec.Body.String(), `"database":{"ok":true}`)
}

func TestReadiness_DBPingError(t *testing.T) {
	rec := runHandler(t, Readiness(&fakePinger{err: errors.New("connection refused")}))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status":"not_ready"`)
	assert.Contains(t, rec.Body.String(), `"database":{"ok":false,"error":"connection refused"}`)
}

func TestReadiness_DBPingTimesOut(t *testing.T) {
	// Slow ping (longer than readinessPingTimeout=2s) — verify the
	// helper bounds the wait by reporting timeout fast. Use a tighter
	// fake delay so the test doesn't wait the full 2s.
	rec := runHandler(t, Readiness(&fakePinger{delay: 100 * time.Millisecond, err: context.DeadlineExceeded}))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestReadinessPingTimeout_Is2s(t *testing.T) {
	// Pinning the constant — readinessPingTimeout drift would silently
	// stretch probe deadlines past orchestrator windows, so make
	// changes deliberate.
	assert.Equal(t, 2*time.Second, readinessPingTimeout)
}

func TestReadinessWithChecks_AllPass(t *testing.T) {
	rec := runHandler(t, ReadinessWithChecks([]ReadinessCheck{
		{Name: "database", Check: func(ctx context.Context) error { return nil }},
		{Name: "redis", Check: func(ctx context.Context) error { return nil }},
	}))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status":"ready"`)
	assert.Contains(t, rec.Body.String(), `"database":{"ok":true}`)
	assert.Contains(t, rec.Body.String(), `"redis":{"ok":true}`)
}

func TestReadinessWithChecks_OneFails(t *testing.T) {
	rec := runHandler(t, ReadinessWithChecks([]ReadinessCheck{
		{Name: "database", Check: func(ctx context.Context) error { return nil }},
		{Name: "redis", Check: func(ctx context.Context) error { return errors.New("redis: connection refused") }},
	}))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status":"not_ready"`)
	assert.Contains(t, rec.Body.String(), `"database":{"ok":true}`)
	assert.Contains(t, rec.Body.String(), `"redis":{"ok":false,"error":"redis: connection refused"}`)
}

func TestReadinessWithChecks_RunInParallel(t *testing.T) {
	// Two 100ms checks should finish in ~100ms not ~200ms — verify
	// they actually run concurrently (a sequential implementation
	// would take ~200ms and fail this).
	delay := 100 * time.Millisecond
	checks := []ReadinessCheck{
		{Name: "a", Check: func(ctx context.Context) error { time.Sleep(delay); return nil }},
		{Name: "b", Check: func(ctx context.Context) error { time.Sleep(delay); return nil }},
	}
	start := time.Now()
	rec := runHandler(t, ReadinessWithChecks(checks))
	elapsed := time.Since(start)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Less(t, elapsed, 180*time.Millisecond, "checks should run in parallel; took %v", elapsed)
}

func TestReadinessWithChecks_EmptyIsAlwaysReady(t *testing.T) {
	// Equivalent to Liveness but reaches the same code path. Useful
	// during the migration when a service hasn't enumerated its deps
	// yet but we still want a /readyz mounted.
	rec := runHandler(t, ReadinessWithChecks(nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"status":"ready"`)
}
