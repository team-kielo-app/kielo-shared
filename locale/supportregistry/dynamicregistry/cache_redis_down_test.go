package dynamicregistry

import (
	"context"
	"testing"
	"time"

	redisv9 "github.com/redis/go-redis/v9"

	"github.com/team-kielo-app/kielo-shared/redisx"
	"github.com/team-kielo-app/kielo-shared/testutil/redisdown"
)

func TestRedisCacheDownDegradesToMissQuickly(t *testing.T) {
	cases := map[string]func(testing.TB) string{
		"refused": redisdown.Refused,
		"hang":    redisdown.Hang,
	}
	for name, addr := range cases {
		t.Run(name, func(t *testing.T) {
			rdb := redisv9.NewClient(redisx.Harden(&redisv9.Options{Addr: addr(t)}))
			t.Cleanup(func() { _ = rdb.Close() })
			c := NewRedisCache(rdb)
			ctx := context.Background()

			start := time.Now()
			if _, _, cached := c.Get(ctx, "k"); cached {
				t.Fatal("Get reported a cached entry")
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("Get took %v with Redis down, want under 1s", elapsed)
			}
			_ = c.Set(ctx, "k", "v", time.Minute)
			_ = c.SetNegative(ctx, "k2", time.Minute)
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("three calls took %v with Redis down", elapsed)
			}
		})
	}
}
