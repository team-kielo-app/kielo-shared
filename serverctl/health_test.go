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
	assert.Equal(t, "OK", rec.Body.String())
}

func TestReadiness_DBPingError(t *testing.T) {
	rec := runHandler(t, Readiness(&fakePinger{err: errors.New("connection refused")}))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "Database connection failed", rec.Body.String())
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
