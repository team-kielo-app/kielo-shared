package recentshown

import (
	"context"
	"testing"
	"time"

	redisv9 "github.com/redis/go-redis/v9"

	"github.com/team-kielo-app/kielo-shared/redisx"
	"github.com/team-kielo-app/kielo-shared/testutil/redisdown"
)

func TestStoreRedisDownReturnsEmptyQuickly(t *testing.T) {
	cases := map[string]func(testing.TB) string{
		"refused": redisdown.Refused,
		"hang":    redisdown.Hang,
	}
	for name, addr := range cases {
		t.Run(name, func(t *testing.T) {
			rdb := redisv9.NewClient(redisx.Harden(&redisv9.Options{Addr: addr(t)}))
			t.Cleanup(func() { _ = rdb.Close() })
			s := New(rdb)
			now := time.Now()

			start := time.Now()
			s.Record(context.Background(), "u1", "feed", []string{"a", "b"}, now)
			got, err := s.Recent(context.Background(), "u1", "feed", now)
			if err != nil || len(got) != 0 {
				t.Fatalf("Recent = %v, %v; want empty, nil", got, err)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("Record+Recent took %v with Redis down, want under 1s", elapsed)
			}
		})
	}
}
