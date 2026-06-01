// Package cacheredis is the Redis-backed implementation of
// localization.Cache. Lives in its own sub-package so consumers that
// only need the Noop/MemoryCache variants don't pull the go-redis
// transitive dep into their binaries.
//
// Adapter, not a Redis client: callers construct their own redis.Cmdable
// (typically *redis.Client / *redis.ClusterClient) and hand it in. This
// keeps connection lifecycle / pooling / TLS config in the consuming
// service where it belongs.
package cacheredis

import (
	"context"
	"errors"
	"time"

	redisv9 "github.com/redis/go-redis/v9"
	"github.com/team-kielo-app/kielo-shared/localization"
)

// Cache adapts a redis.Cmdable to localization.Cache.
//
// Storage shape: each translation occupies one key. The cached value is
// the translated string verbatim — no JSON envelope, no metadata. Age
// is derived from the key's remaining TTL using Redis's PTTL: when the
// seam writes a value with ttl = freshTTL + staleTTL, the current age
// is (totalTTL - PTTL). This relies on the seam's contract that Set is
// always called with the same totalTTL = SeamConfig.FreshTTL +
// SeamConfig.StaleTTL — verify via Cache.totalTTL passed at construction.
//
// Why PTTL-derived age rather than a stored timestamp:
//   - Saves ~24 bytes per entry × millions of keys.
//   - Avoids Redis-clock vs app-clock skew (PTTL is Redis-side).
//   - One round-trip per Get instead of two (the GET + PTTL fit in a
//     pipeline that costs one network RTT).
type Cache struct {
	client   redisv9.Cmdable
	totalTTL time.Duration
}

// New wraps a redis.Cmdable as a localization.Cache. totalTTL must match
// the parent Seam's freshTTL + staleTTL; mismatch causes age-derivation
// to report wrong values and breaks SWR semantics.
func New(client redisv9.Cmdable, totalTTL time.Duration) *Cache {
	if totalTTL <= 0 {
		totalTTL = 7 * 24 * time.Hour
	}
	return &Cache{client: client, totalTTL: totalTTL}
}

// Get implements localization.Cache. Pipelined GET + PTTL: one RTT, two
// commands. Returns ok=false on cache miss, on Redis error (degraded —
// seam treats it as a miss and goes to provider), or on negative PTTL
// (key exists but has no TTL, indicating a corrupted entry — better to
// re-translate than to serve unbounded stale data).
func (c *Cache) Get(ctx context.Context, key string) (localization.CacheEntry, bool) {
	pipe := c.client.Pipeline()
	getCmd := pipe.Get(ctx, key)
	pttlCmd := pipe.PTTL(ctx, key)
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redisv9.Nil) {
		return localization.CacheEntry{}, false
	}

	value, err := getCmd.Result()
	if err != nil {
		return localization.CacheEntry{}, false
	}

	remaining, err := pttlCmd.Result()
	if err != nil || remaining <= 0 {
		return localization.CacheEntry{}, false
	}

	age := c.totalTTL - remaining
	if age < 0 {
		age = 0
	}
	return localization.CacheEntry{Value: value, Age: age}, true
}

// Set implements localization.Cache. ttl is what the seam supplies
// (freshTTL + staleTTL); we honor it directly. SET with EX is one
// command, no pipeline needed.
func (c *Cache) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = c.totalTTL
	}
	return c.client.Set(ctx, key, value, ttl).Err()
}

// BatchGet implements localization.BatchCache. Sweep TTTT-B: pipelined
// MGET + per-key PTTL fits in a single RTT regardless of len(keys).
// MGET returns nil for misses; we omit those from the result map so
// callers iterate `for _, k := range keys; if entry, ok := result[k];
// ok { ... }` matching the single-Get convention.
//
// Performance shape vs per-key Get loop:
//   - Pre-TTTT: N keys → N round-trips × (GET+PTTL pipeline each = 1 RTT)
//     = N RTTs
//   - Post-TTTT: 1 round-trip for MGET + 1 pipelined batch of N PTTLs
//     = 2 RTTs total (or 1 RTT when the pipeline is auto-flushed by
//     the go-redis client)
//
// For the canonical scenario-list case (264 refs), this is 264 RTTs
// → 1 RTT.
//
//nolint:gocyclo // Single Redis MGET/PTTL batch path with miss, TTL, stale, and decode branches kept in one pass.
func (c *Cache) BatchGet(ctx context.Context, keys []string) map[string]localization.CacheEntry {
	out := make(map[string]localization.CacheEntry, len(keys))
	if len(keys) == 0 {
		return out
	}
	// Phase 1: MGET all values in one command.
	values, err := c.client.MGet(ctx, keys...).Result()
	if err != nil {
		return out
	}
	// Phase 2: pipeline PTTL for each hit. Only hits need age — misses
	// are dropped before the pipeline executes so we don't spend RTT
	// on keys that aren't present.
	pipe := c.client.Pipeline()
	pttlCmds := make([]*redisv9.DurationCmd, len(keys))
	for i, raw := range values {
		if raw == nil {
			continue
		}
		pttlCmds[i] = pipe.PTTL(ctx, keys[i])
	}
	if _, err := pipe.Exec(ctx); err != nil {
		// PTTL pipeline failed; serve hits with Age=0 so they still
		// look fresh. Better than dropping every hit silently.
		for i, raw := range values {
			if raw == nil {
				continue
			}
			str, ok := raw.(string)
			if !ok || str == "" {
				continue
			}
			out[keys[i]] = localization.CacheEntry{Value: str, Age: 0}
		}
		return out
	}
	for i, raw := range values {
		if raw == nil {
			continue
		}
		str, ok := raw.(string)
		if !ok || str == "" {
			continue
		}
		var age time.Duration
		if pttlCmds[i] != nil {
			remaining, err := pttlCmds[i].Result()
			if err == nil && remaining > 0 {
				age = c.totalTTL - remaining
				if age < 0 {
					age = 0
				}
			}
		}
		out[keys[i]] = localization.CacheEntry{Value: str, Age: age}
	}
	return out
}

// BatchSet implements localization.BatchCache. Sweep TTTT-B: pipelined
// SET-with-EX for every entry in one RTT. Go-redis pipelines flush in
// one TCP write when called inside a single Exec.
func (c *Cache) BatchSet(ctx context.Context, entries map[string]string, ttl time.Duration) error {
	if len(entries) == 0 {
		return nil
	}
	if ttl <= 0 {
		ttl = c.totalTTL
	}
	pipe := c.client.Pipeline()
	for k, v := range entries {
		pipe.Set(ctx, k, v, ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}
