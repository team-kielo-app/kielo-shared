package middleware

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

// These tests require a reachable Redis (CI hits the same docker-compose
// instance dev uses on 127.0.0.1:6379). Skips when Redis isn't up so
// CI-without-infra runs cleanly.

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := "127.0.0.1:6379"
	rdb := redis.NewClient(&redis.Options{Addr: addr, DB: 15})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("redis not reachable at %s; skipping (%v)", addr, err)
	}
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		t.Skipf("redis flushdb failed (%v); skipping", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_ = rdb.FlushDB(ctx).Err()
		_ = rdb.Close()
	})
	return rdb
}

func TestIdempotency_PassesThroughGet(t *testing.T) {
	rdb := newTestRedis(t)
	mw := Idempotency(IdempotencyOptions{Redis: rdb})

	var calls int32
	handler := mw(func(c echo.Context) error {
		atomic.AddInt32(&calls, 1)
		return c.String(http.StatusOK, "ok")
	})

	e := echo.New()
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/me/profile", nil)
		req.Header.Set("Idempotency-Key", "should-be-ignored-on-GET")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/me/profile")
		if err := handler(c); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("GET should always pass through; calls=%d, want 3", got)
	}
}

func TestIdempotency_PassesThroughWithoutHeader(t *testing.T) {
	rdb := newTestRedis(t)
	mw := Idempotency(IdempotencyOptions{Redis: rdb})

	var calls int32
	handler := mw(func(c echo.Context) error {
		atomic.AddInt32(&calls, 1)
		return c.JSON(http.StatusOK, map[string]string{"ok": "1"})
	})

	e := echo.New()
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/me/scenarios", bytes.NewReader([]byte("{}")))
		// No Idempotency-Key header — opt-in by client.
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/me/scenarios")
		if err := handler(c); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("missing key should not dedup; calls=%d, want 3", got)
	}
}

func TestIdempotency_SecondPostReplaysCached(t *testing.T) {
	rdb := newTestRedis(t)
	mw := Idempotency(IdempotencyOptions{
		Redis: rdb,
		Subject: func(c echo.Context) string {
			return "user-123"
		},
	})

	var calls int32
	handler := mw(func(c echo.Context) error {
		atomic.AddInt32(&calls, 1)
		return c.JSON(http.StatusCreated, map[string]string{"id": "scenario-A"})
	})

	e := echo.New()
	doRequest := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/me/scenarios", bytes.NewReader([]byte("{}")))
		req.Header.Set("Idempotency-Key", "client-key-7")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/me/scenarios")
		if err := handler(c); err != nil {
			t.Fatalf("handler error: %v", err)
		}
		return rec
	}

	first := doRequest()
	if first.Code != http.StatusCreated {
		t.Fatalf("first response code = %d, want 201", first.Code)
	}
	second := doRequest()
	if second.Code != http.StatusCreated {
		t.Fatalf("second response code = %d, want 201", second.Code)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("handler should run exactly once; calls=%d", got)
	}
	if !strings.Contains(second.Body.String(), "scenario-A") {
		t.Errorf("replay should return cached body; got %q", second.Body.String())
	}
	if second.Header().Get("Idempotent-Replayed") != "true" {
		t.Errorf("replay should set Idempotent-Replayed header; got %q",
			second.Header().Get("Idempotent-Replayed"))
	}
}

func TestIdempotency_ErrorResponseNotCached(t *testing.T) {
	rdb := newTestRedis(t)
	mw := Idempotency(IdempotencyOptions{Redis: rdb})

	var calls int32
	handler := mw(func(c echo.Context) error {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			return echo.NewHTTPError(http.StatusServiceUnavailable, "transient")
		}
		return c.JSON(http.StatusCreated, map[string]string{"id": "scenario-B"})
	})

	e := echo.New()
	doRequest := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/me/scenarios", bytes.NewReader([]byte("{}")))
		req.Header.Set("Idempotency-Key", "client-key-9")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/me/scenarios")
		_ = handler(c)
		return rec
	}

	_ = doRequest() // 503
	second := doRequest()
	if second.Code != http.StatusCreated {
		t.Errorf("retry past failure should re-run handler; got status %d", second.Code)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("handler should be invoked twice (failure + retry); calls=%d", got)
	}
}

func TestIdempotency_FlushSwitchesToPassThroughAndSkipsCache(t *testing.T) {
	rdb := newTestRedis(t)
	mw := Idempotency(IdempotencyOptions{Redis: rdb})

	var calls int32
	handler := mw(func(c echo.Context) error {
		atomic.AddInt32(&calls, 1)
		c.Response().WriteHeader(http.StatusOK)
		if _, err := c.Response().Write([]byte("a")); err != nil {
			return err
		}
		c.Response().Flush()
		_, err := c.Response().Write([]byte("b"))
		return err
	})

	e := echo.New()
	doRequest := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/stream", bytes.NewReader([]byte("{}")))
		req.Header.Set("Idempotency-Key", "stream-key")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/stream")
		if err := handler(c); err != nil {
			t.Fatalf("handler error: %v", err)
		}
		return rec
	}

	first := doRequest()
	second := doRequest()
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf(
			"flushed responses must not be cached; calls=%d, want 2; first=%d/%q second=%d/%q replay=%q",
			got, first.Code, first.Body.String(), second.Code, second.Body.String(), second.Header().Get("Idempotent-Replayed"),
		)
	}
	if first.Body.String() != "ab" || second.Body.String() != "ab" {
		t.Fatalf("flushed response body mismatch: first=%q second=%q", first.Body.String(), second.Body.String())
	}
	if second.Header().Get("Idempotent-Replayed") != "" {
		t.Fatalf("flushed response should not be replayed, got header %q", second.Header().Get("Idempotent-Replayed"))
	}
}

func TestIdempotency_DifferentSubjectsDontShare(t *testing.T) {
	rdb := newTestRedis(t)

	currentSubject := "user-A"
	mw := Idempotency(IdempotencyOptions{
		Redis: rdb,
		Subject: func(c echo.Context) string {
			return currentSubject
		},
	})

	var calls int32
	handler := mw(func(c echo.Context) error {
		atomic.AddInt32(&calls, 1)
		return c.JSON(http.StatusCreated, map[string]string{"id": "x"})
	})

	e := echo.New()
	doRequest := func() {
		req := httptest.NewRequest(http.MethodPost, "/me/scenarios", bytes.NewReader([]byte("{}")))
		req.Header.Set("Idempotency-Key", "shared-key")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/me/scenarios")
		_ = handler(c)
	}

	currentSubject = "user-A"
	doRequest()
	currentSubject = "user-B"
	doRequest()
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("different subjects should not share idempotency slot; calls=%d", got)
	}
}

func TestIdempotency_OversizedKeyRejected(t *testing.T) {
	rdb := newTestRedis(t)
	mw := Idempotency(IdempotencyOptions{Redis: rdb, KeyMaxLen: 32})

	handler := mw(func(c echo.Context) error {
		return c.NoContent(http.StatusCreated)
	})

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/me/scenarios", bytes.NewReader([]byte("{}")))
	req.Header.Set("Idempotency-Key", strings.Repeat("x", 100))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/me/scenarios")
	err := handler(c)
	if err == nil {
		t.Fatal("expected error for oversized key")
	}
	if he, ok := err.(*echo.HTTPError); !ok || he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 HTTPError, got %v", err)
	}
}

func TestIdempotency_NilRedisIsNoOp(t *testing.T) {
	// Lets services wire the middleware unconditionally and flip Redis
	// on later without code changes. Verify it doesn't blow up.
	mw := Idempotency(IdempotencyOptions{Redis: nil})

	var calls int32
	handler := mw(func(c echo.Context) error {
		atomic.AddInt32(&calls, 1)
		return c.NoContent(http.StatusCreated)
	})

	e := echo.New()
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/me/scenarios", nil)
		req.Header.Set("Idempotency-Key", "any-key")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/me/scenarios")
		_ = handler(c)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("nil Redis should be no-op; calls=%d, want 3", got)
	}
}

// quiet linter — the `time` import is used by the responseTTL/lockTTL
// types; if those go away the import would too.
var _ = time.Second
