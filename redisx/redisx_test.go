package redisx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
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

func TestNewClientPaysOneTimeoutForManyCalls(t *testing.T) {
	cases := map[string]func(testing.TB) string{
		"refused": redisdown.Refused,
		"hang":    redisdown.Hang,
	}
	for name, addr := range cases {
		t.Run(name, func(t *testing.T) {
			rdb := New(&redis.Options{Addr: addr(t)})
			t.Cleanup(func() { _ = rdb.Close() })

			start := time.Now()
			for i := 0; i < 20; i++ {
				if err := rdb.Get(context.Background(), "k").Err(); err == nil {
					t.Fatal("Get against a down Redis returned no error")
				}
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("20 calls took %v, want under 1s", elapsed)
			}
		})
	}
}

func TestBreakerOpensAndRecovers(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(Harden(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = rdb.Close() })
	rdb.AddHook(NewBreaker(2, 200*time.Millisecond))
	ctx := context.Background()

	if err := rdb.Set(ctx, "k", "v", 0).Err(); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := rdb.Get(ctx, "missing").Err(); !errors.Is(err, redis.Nil) {
		t.Fatalf("Get missing = %v, want redis.Nil", err)
	}

	mr.Close()
	for i := 0; i < 2; i++ {
		_ = rdb.Get(ctx, "k").Err()
	}
	if err := rdb.Get(ctx, "k").Err(); !errors.Is(err, ErrBreakerOpen) {
		t.Fatalf("after two failures Get = %v, want ErrBreakerOpen", err)
	}

	if err := mr.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if err := rdb.Set(ctx, "k", "v", 0).Err(); err != nil {
		t.Fatalf("probe after cooldown failed: %v", err)
	}
	if got, err := rdb.Get(ctx, "k").Result(); err != nil || got != "v" {
		t.Fatalf("Get after recovery = %q, %v", got, err)
	}
}

func TestBreakerIgnoresRedisReportedErrors(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(Harden(&redis.Options{Addr: mr.Addr()}))
	t.Cleanup(func() { _ = rdb.Close() })
	rdb.AddHook(NewBreaker(1, time.Minute))
	ctx := context.Background()

	if err := rdb.Set(ctx, "str", "v", 0).Err(); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := rdb.LPush(ctx, "str", "x").Err(); err == nil {
		t.Fatal("LPush on a string key succeeded")
	}
	if err := rdb.Get(ctx, "str").Err(); err != nil {
		t.Fatalf("Get after a WRONGTYPE reply = %v, want success", err)
	}
}
