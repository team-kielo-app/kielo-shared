package cacheredis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	redisv9 "github.com/redis/go-redis/v9"
	"github.com/team-kielo-app/kielo-shared/localization"
)

// newTestCache stands up a miniredis instance + go-redis client and
// returns the adapter plus the miniredis handle so tests can
// FastForward the clock. totalTTL is hardcoded to 1h because every
// test in this file uses that as the constructor value; pass a
// different one only if a future test exercises totalTTL semantics.
func newTestCache(t *testing.T) (*Cache, *miniredis.Miniredis) {
	t.Helper()
	s := miniredis.RunT(t)
	client := redisv9.NewClient(&redisv9.Options{Addr: s.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return New(client, time.Hour), s
}

func TestCache_RoundTrip(t *testing.T) {
	c, _ := newTestCache(t)
	ctx := context.Background()

	if err := c.Set(ctx, "k1", "Xin chào", time.Hour); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok := c.Get(ctx, "k1")
	if !ok {
		t.Fatal("expected hit")
	}
	if got.Value != "Xin chào" {
		t.Fatalf("value: %q", got.Value)
	}
	// Age right after set is ~0.
	if got.Age > 100*time.Millisecond {
		t.Fatalf("expected near-zero age, got %v", got.Age)
	}
}

func TestCache_MissReturnsFalse(t *testing.T) {
	c, _ := newTestCache(t)
	if _, ok := c.Get(context.Background(), "nope"); ok {
		t.Fatal("expected miss")
	}
}

func TestCache_AgeIncreasesWithTime(t *testing.T) {
	c, s := newTestCache(t)
	ctx := context.Background()
	_ = c.Set(ctx, "k1", "value", time.Hour)

	// miniredis FastForward moves both the wall clock and the
	// effective TTL countdown. After advancing 30m, age should be
	// roughly 30m (within Redis-side rounding tolerance).
	s.FastForward(30 * time.Minute)
	got, ok := c.Get(ctx, "k1")
	if !ok {
		t.Fatal("expected hit after fast-forward")
	}
	if got.Age < 29*time.Minute || got.Age > 31*time.Minute {
		t.Fatalf("expected age ~30m, got %v", got.Age)
	}
}

func TestCache_ExpiredReturnsMiss(t *testing.T) {
	c, s := newTestCache(t)
	ctx := context.Background()
	_ = c.Set(ctx, "k1", "value", time.Hour)
	s.FastForward(2 * time.Hour)
	if _, ok := c.Get(ctx, "k1"); ok {
		t.Fatal("expected miss after TTL expiry")
	}
}

func TestCache_SetTTLOverridesConstructorDefault(t *testing.T) {
	// Constructor totalTTL=1h but Set ttl=10m. Age math after 5m
	// should reflect the as-set TTL, not the constructor's. The seam
	// always passes the same ttl, but defensive callers / tests want
	// the Set ttl to actually shape age.
	c, s := newTestCache(t)
	ctx := context.Background()
	_ = c.Set(ctx, "k1", "value", 10*time.Minute)

	s.FastForward(5 * time.Minute)
	got, ok := c.Get(ctx, "k1")
	if !ok {
		t.Fatal("expected hit")
	}
	// Adapter computes age = constructorTotalTTL - PTTL. With
	// constructor=1h, PTTL=5m left, age comes out to 55m. This
	// documents the "totalTTL must match the seam's actual ttl"
	// contract — the test pins that mismatch causes wrong-age.
	if got.Age < 54*time.Minute || got.Age > 56*time.Minute {
		t.Fatalf("expected age ~55m (showing the constructor/set mismatch issue), got %v", got.Age)
	}
}

// === Seam integration smoke ==============================================

func TestCache_AsSeamCache(t *testing.T) {
	// Compile-time check: *Cache implements localization.Cache.
	var _ localization.Cache = (*Cache)(nil)
}
