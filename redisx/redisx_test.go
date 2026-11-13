package redisx

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/team-kielo-app/kielo-shared/testutil/redisdown"
)

func TestHardenedClientGivesUpQuicklyWhenRedisIsDown(t *testing.T) {
	cases := map[string]func(testing.TB) string{
		"refused": redisdown.Refused,
		"hang":    redisdown.Hang,
	}
	for name, addr := range cases {
		t.Run(name, func(t *testing.T) {
			rdb := redis.NewClient(Harden(&redis.Options{Addr: addr(t)}))
			t.Cleanup(func() { _ = rdb.Close() })

			start := time.Now()
			if err := rdb.Get(context.Background(), "k").Err(); err == nil {
				t.Fatal("Get against a down Redis returned no error")
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("Get took %v, want under 1s", elapsed)
			}
		})
	}
}

func TestHardenedClientHonorsContextDeadline(t *testing.T) {
	rdb := redis.NewClient(Harden(&redis.Options{Addr: redisdown.Hang(t)}))
	t.Cleanup(func() { _ = rdb.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_ = rdb.Get(ctx, "k").Err()
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("Get took %v with a 100ms context, want under 250ms", elapsed)
	}
}
