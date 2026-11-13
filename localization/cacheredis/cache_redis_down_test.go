package cacheredis

import (
	"context"
	"testing"
	"time"

	redisv9 "github.com/redis/go-redis/v9"

	"github.com/team-kielo-app/kielo-shared/redisx"
	"github.com/team-kielo-app/kielo-shared/testutil/redisdown"
)

func TestCacheRedisDownDegradesToMissQuickly(t *testing.T) {
	cases := map[string]func(testing.TB) string{
		"refused": redisdown.Refused,
		"hang":    redisdown.Hang,
	}
	for name, addr := range cases {
		t.Run(name, func(t *testing.T) {
			rdb := redisv9.NewClient(redisx.Harden(&redisv9.Options{Addr: addr(t)}))
			t.Cleanup(func() { _ = rdb.Close() })
			c := New(rdb, time.Hour)
			ctx := context.Background()

			start := time.Now()
			if _, ok := c.Get(ctx, "k"); ok {
				t.Fatal("Get reported a hit")
			}
			if got := c.BatchGet(ctx, []string{"a", "b"}); len(got) != 0 {
				t.Fatalf("BatchGet returned %d entries", len(got))
			}
			_ = c.Set(ctx, "k", "v", time.Minute)
			_ = c.BatchSet(ctx, map[string]string{"a": "1"}, time.Minute)
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("four calls took %v with Redis down", elapsed)
			}
		})
	}
}

func TestCacheRedisDownEachCallUnderOneSecond(t *testing.T) {
	rdb := redisv9.NewClient(redisx.Harden(&redisv9.Options{Addr: redisdown.Hang(t)}))
	t.Cleanup(func() { _ = rdb.Close() })
	c := New(rdb, time.Hour)

	start := time.Now()
	c.Get(context.Background(), "k")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Get took %v against a hung Redis, want under 1s", elapsed)
	}
}
