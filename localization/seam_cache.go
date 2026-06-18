package localization

import (
	"context"
	"sync"
	"time"
)

// Cache is the seam's translation cache abstraction. The seam reads
// cache hits with their age so it can decide between serving fresh,
// serving stale + kicking off a background refresh, or treating as a
// miss. Concrete implementations live in service-side packages so this
// shared library doesn't pull in a Redis client.
//
// Sweep TTTT-B: BatchGet + BatchSet added so list-of-refs callers
// (Seam.TranslateBatch) issue ONE Redis pipelined MGET+PTTL instead of
// N sequential GETs. Backward-compat default implementations route
// through Get/Set so existing Cache impls continue to work without
// the batch optimization; production impls (cacheredis) override.
type Cache interface {
	Get(ctx context.Context, key string) (CacheEntry, bool)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
}

// BatchCache is the optional batch-aware interface. Impls that
// implement this surface get a true single-RTT batch path; impls that
// don't continue to work via Cache.Get/Set fallback in the seam's
// batch fan-out logic.
type BatchCache interface {
	Cache
	// BatchGet returns a map from key → entry for every key that hit.
	// Misses are omitted from the map (callers iterate `for _, k :=
	// range keys; if entry, ok := result[k]; ok { ... }`). One round-
	// trip to the backing store regardless of len(keys).
	BatchGet(ctx context.Context, keys []string) map[string]CacheEntry
	// BatchSet writes multiple key→value pairs with a common TTL in
	// one round-trip. Implementations should pipeline the writes.
	BatchSet(ctx context.Context, entries map[string]string, ttl time.Duration) error
}

// CacheEntry is a cache hit with the time since it was written. Age >
// freshTTL signals stale-while-revalidate territory; Age > freshTTL +
// staleTTL means the implementation should have returned ok=false
// (entry is past its useful life).
type CacheEntry struct {
	Value string
	Age   time.Duration
}

// NoopCache is a Cache that never hits. Use in unit tests + services
// running without Redis. The seam still works — every translation just
// goes to the provider.
type NoopCache struct{}

func (NoopCache) Get(context.Context, string) (CacheEntry, bool)           { return CacheEntry{}, false }
func (NoopCache) Set(context.Context, string, string, time.Duration) error { return nil }

// MemoryCache is a simple in-memory cache implementation suitable for
// unit tests and dev environments. Not safe for production: no size
// limits, no eviction beyond TTL, single-process only. Production
// services should plug in a Redis-backed Cache.
type MemoryCache struct {
	mu      sync.RWMutex
	entries map[string]memoryEntry
	now     func() time.Time
}

type memoryEntry struct {
	value     string
	writtenAt time.Time
	expiresAt time.Time
}

// NewMemoryCache returns an empty MemoryCache. Pass a custom now()
// function for deterministic tests; pass nil for time.Now.
func NewMemoryCache(now func() time.Time) *MemoryCache {
	if now == nil {
		now = time.Now
	}
	return &MemoryCache{
		entries: make(map[string]memoryEntry),
		now:     now,
	}
}

func (c *MemoryCache) Get(_ context.Context, key string) (CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok {
		return CacheEntry{}, false
	}
	now := c.now()
	if now.After(entry.expiresAt) {
		return CacheEntry{}, false
	}
	return CacheEntry{
		Value: entry.value,
		Age:   now.Sub(entry.writtenAt),
	}, true
}

func (c *MemoryCache) Set(_ context.Context, key, value string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.entries[key] = memoryEntry{
		value:     value,
		writtenAt: now,
		expiresAt: now.Add(ttl),
	}
	return nil
}
