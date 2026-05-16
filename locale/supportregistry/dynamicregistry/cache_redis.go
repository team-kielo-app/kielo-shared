package dynamicregistry

import (
	"context"
	"errors"
	"time"

	redisv9 "github.com/redis/go-redis/v9"
)

// negativeSentinel is stored in Redis to represent "cached-negative —
// no override exists for this key". Chosen to be a value that can
// never legitimately be a translated_text (no real translation starts
// with the NUL byte). Lookup compares against this exact string.
const negativeSentinel = "\x00neg"

// RedisCache is a small Redis-backed Cache implementation for
// dynamicregistry. Distinct from kielo-shared/localization/cacheredis
// because the SWR/age semantics that cache implements aren't useful
// here — DynamicRegistry only needs straight GET/SET with TTL.
//
// Adapter, not a client: callers supply their own redis.Cmdable.
type RedisCache struct {
	client redisv9.Cmdable
}

// NewRedisCache wraps a redis.Cmdable as a dynamicregistry.Cache.
func NewRedisCache(client redisv9.Cmdable) *RedisCache {
	return &RedisCache{client: client}
}

// Get implements Cache. Returns (value, isOverride, cachedOK).
//
// Cached-positive: returns (override-text, true, true).
// Cached-negative: returns ("", false, true).
// Cache miss / Redis error: returns ("", false, false). Caller probes DB.
func (c *RedisCache) Get(ctx context.Context, key string) (value string, isOverride, cachedOK bool) {
	if c == nil || c.client == nil {
		return "", false, false
	}
	value, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redisv9.Nil) {
			return "", false, false
		}
		// Redis error: degrade by treating as miss. Caller probes DB.
		return "", false, false
	}
	if value == negativeSentinel {
		return "", false, true
	}
	return value, true, true
}

// Set implements Cache. Caches a positive override hit with the given TTL.
func (c *RedisCache) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if c == nil || c.client == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = DefaultHitTTL
	}
	return c.client.Set(ctx, key, value, ttl).Err()
}

// SetNegative implements Cache. Caches a "no override exists" sentinel
// with the (typically shorter) miss TTL.
func (c *RedisCache) SetNegative(ctx context.Context, key string, ttl time.Duration) error {
	if c == nil || c.client == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = DefaultMissTTL
	}
	return c.client.Set(ctx, key, negativeSentinel, ttl).Err()
}

// Compile-time assertion that *RedisCache satisfies Cache.
var _ Cache = (*RedisCache)(nil)

// NoopCache is a Cache that never caches anything — every Get is a miss
// and every Set is silently dropped. Useful for tests and for the
// "strict consistency" mode where every Resolve must hit the DB.
type NoopCache struct{}

// Get implements Cache. Always reports cache miss.
func (NoopCache) Get(_ context.Context, _ string) (value string, isOverride, cachedOK bool) {
	return "", false, false
}

// Set implements Cache. No-op.
func (NoopCache) Set(_ context.Context, _, _ string, _ time.Duration) error { return nil }

// SetNegative implements Cache. No-op.
func (NoopCache) SetNegative(_ context.Context, _ string, _ time.Duration) error { return nil }

// Compile-time assertion that NoopCache satisfies Cache.
var _ Cache = NoopCache{}
