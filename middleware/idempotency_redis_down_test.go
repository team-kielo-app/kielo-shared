package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"

	"github.com/team-kielo-app/kielo-shared/redisx"
	"github.com/team-kielo-app/kielo-shared/testutil/redisdown"
)

func TestIdempotency_RedisDownFailsOpen(t *testing.T) {
	cases := map[string]func(testing.TB) string{
		"refused": redisdown.Refused,
		"hang":    redisdown.Hang,
	}
	for name, addr := range cases {
		t.Run(name, func(t *testing.T) {
			rdb := redis.NewClient(redisx.Harden(&redis.Options{Addr: addr(t)}))
			t.Cleanup(func() { _ = rdb.Close() })
			mw := Idempotency(IdempotencyOptions{Redis: rdb})

			var calls int32
			handler := mw(func(c echo.Context) error {
				atomic.AddInt32(&calls, 1)
				return c.String(http.StatusOK, "done")
			})

			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/me/items", nil)
			req.Header.Set("Idempotency-Key", "k-1")
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetPath("/me/items")

			start := time.Now()
			err := handler(c)
			elapsed := time.Since(start)

			if err != nil {
				t.Fatalf("handler: %v", err)
			}
			if rec.Code != http.StatusOK || rec.Body.String() != "done" {
				t.Fatalf("got %d %q, want 200 done", rec.Code, rec.Body.String())
			}
			if got := atomic.LoadInt32(&calls); got != 1 {
				t.Fatalf("handler ran %d times, want 1", got)
			}
			if elapsed > time.Second {
				t.Fatalf("request took %v with Redis down, want under 1s", elapsed)
			}
		})
	}
}
