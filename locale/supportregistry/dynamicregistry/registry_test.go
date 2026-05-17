package dynamicregistry

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/team-kielo-app/kielo-shared/locale/supportregistry"
)

// Shared seed builder. Returns a finalized MapRegistry with three keys
// across en/vi/sv: greeting (all 3), farewell (en+vi only), unknown is
// absent — used to cover the "no English seed → skip override layer"
// branch.
func buildSeed(t *testing.T) supportregistry.Registry {
	t.Helper()
	r := supportregistry.New([]string{"en", "vi", "sv"})
	require.True(t, r.Set("ui.greeting", "en", "Hello"))
	require.True(t, r.Set("ui.greeting", "vi", "Xin chào"))
	require.True(t, r.Set("ui.greeting", "sv", "Hej"))
	require.True(t, r.Set("ui.farewell", "en", "Goodbye"))
	require.True(t, r.Set("ui.farewell", "vi", "Tạm biệt"))
	r.Finalize()
	return r
}

// ---------------------------------------------------------------------------
// Stub Cache (positive hit / negative hit / miss switching for assertions)
// ---------------------------------------------------------------------------

type stubCache struct {
	mu          sync.Mutex
	store       map[string]string // key → value ("" means negative)
	getCalls    int64
	setCalls    int64
	setNegCalls int64
}

func newStubCache() *stubCache {
	return &stubCache{store: make(map[string]string)}
}

func (s *stubCache) Get(_ context.Context, key string) (value string, isOverride, cachedOK bool) {
	atomic.AddInt64(&s.getCalls, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.store[key]
	if !ok {
		return "", false, false
	}
	if v == "" {
		return "", false, true // cached-negative
	}
	return v, true, true
}

func (s *stubCache) Set(_ context.Context, key, value string, _ time.Duration) error {
	atomic.AddInt64(&s.setCalls, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[key] = value
	return nil
}

func (s *stubCache) SetNegative(_ context.Context, key string, _ time.Duration) error {
	atomic.AddInt64(&s.setNegCalls, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[key] = ""
	return nil
}

// ---------------------------------------------------------------------------
// Stub probe (controllable DB-layer behavior)
// ---------------------------------------------------------------------------

type probeResult struct {
	value string
	found bool
	err   error
}

type stubProbe struct {
	mu      sync.Mutex
	results map[string]probeResult // key = resourceID|sv|locale
	calls   int64
}

func newStubProbe() *stubProbe {
	return &stubProbe{results: make(map[string]probeResult)}
}

func (p *stubProbe) setHit(resourceID, sourceVersion, locale, value string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.results[resourceID+"|"+sourceVersion+"|"+locale] = probeResult{value: value, found: true}
}

func (p *stubProbe) setMiss(resourceID, sourceVersion, locale string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.results[resourceID+"|"+sourceVersion+"|"+locale] = probeResult{found: false}
}

func (p *stubProbe) setError(resourceID, sourceVersion, locale string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.results[resourceID+"|"+sourceVersion+"|"+locale] = probeResult{err: err}
}

func (p *stubProbe) probe(_ context.Context, _ /*resourceType*/, resourceID, sourceVersion, locale string) (value string, found bool, err error) {
	atomic.AddInt64(&p.calls, 1)
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.results[resourceID+"|"+sourceVersion+"|"+locale]
	if !ok {
		// Unspecified key → miss.
		return "", false, nil
	}
	return r.value, r.found, r.err
}

// buildRegistry wires a Registry around a seed, stubProbe, and stubCache.
// Pass cache=nil to test the cache-disabled path.
func buildRegistry(t *testing.T, seed supportregistry.Registry, probe *stubProbe, cache Cache) *Registry {
	t.Helper()
	r := newWithProbe(seed, cache)
	if probe != nil {
		r.probe = probe.probe
	}
	return r
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestResolve_PoolNilDegradesToSeed(t *testing.T) {
	// pool=nil + cache=nil → DynamicRegistry behaves as a pure
	// pass-through over the seed. Critical for the "service hasn't
	// wired the DB yet" deployment path.
	seed := buildSeed(t)
	r := New(seed, nil, nil)
	ctx := context.Background()

	assert.Equal(t, "Xin chào", r.Resolve(ctx, "ui.greeting", "vi"))
	assert.Equal(t, "Hej", r.Resolve(ctx, "ui.greeting", "sv"))
	assert.Equal(t, "Hello", r.Resolve(ctx, "ui.greeting", "en"))
	// Key missing from seed → registry returns key string.
	assert.Equal(t, "ui.unknown", r.Resolve(ctx, "ui.unknown", "vi"))
}

func TestResolve_EnglishLocaleShortCircuitsToSeed(t *testing.T) {
	// English overrides aren't probed — the English seed IS the
	// source-of-truth. This is documented contract; ensure we never
	// hit the cache or DB for "en".
	seed := buildSeed(t)
	cache := newStubCache()
	probe := newStubProbe()
	r := buildRegistry(t, seed, probe, cache)

	got := r.Resolve(context.Background(), "ui.greeting", "en")
	assert.Equal(t, "Hello", got)
	assert.Zero(t, atomic.LoadInt64(&cache.getCalls), "cache must not be consulted for en")
	assert.Zero(t, atomic.LoadInt64(&probe.calls), "DB must not be probed for en")
}

func TestResolve_EmptyLocaleShortCircuitsToSeed(t *testing.T) {
	// Empty locale = "no preference"; the seed's English fallback
	// is the right answer.
	seed := buildSeed(t)
	cache := newStubCache()
	probe := newStubProbe()
	r := buildRegistry(t, seed, probe, cache)

	got := r.Resolve(context.Background(), "ui.greeting", "")
	assert.Equal(t, "Hello", got)
	assert.Zero(t, atomic.LoadInt64(&cache.getCalls))
	assert.Zero(t, atomic.LoadInt64(&probe.calls))
}

func TestResolve_KeyAbsentFromSeedSkipsOverrideLayer(t *testing.T) {
	// Overrides can't exist for keys the seed doesn't know about.
	// Probing for them is wasted work. Ensure we short-circuit.
	seed := buildSeed(t)
	cache := newStubCache()
	probe := newStubProbe()
	r := buildRegistry(t, seed, probe, cache)

	got := r.Resolve(context.Background(), "ui.missing", "vi")
	assert.Equal(t, "ui.missing", got)
	assert.Zero(t, atomic.LoadInt64(&cache.getCalls))
	assert.Zero(t, atomic.LoadInt64(&probe.calls))
}

func TestResolve_CacheHitPositiveReturnsOverride(t *testing.T) {
	seed := buildSeed(t)
	cache := newStubCache()
	probe := newStubProbe()
	r := buildRegistry(t, seed, probe, cache)
	ctx := context.Background()

	// Trigger source-version computation so we know the cache key shape.
	sv, _, ok := r.sourceVersionFor(ctx, "ui.greeting")
	require.True(t, ok)
	cacheKey := r.cacheKeyFor("ui.greeting", sv, "vi")
	require.NoError(t, cache.Set(ctx, cacheKey, "Chào bạn!", time.Minute))

	got := r.Resolve(ctx, "ui.greeting", "vi")
	assert.Equal(t, "Chào bạn!", got, "cached override must win over seed value Xin chào")
	assert.Zero(t, atomic.LoadInt64(&probe.calls), "DB must not be probed on cache hit")
}

func TestResolve_CacheHitNegativeFallsThroughToSeed(t *testing.T) {
	// Cached-negative means definitively no override; skip the DB
	// probe and return the seed value.
	seed := buildSeed(t)
	cache := newStubCache()
	probe := newStubProbe()
	r := buildRegistry(t, seed, probe, cache)
	ctx := context.Background()

	sv, _, _ := r.sourceVersionFor(ctx, "ui.greeting")
	cacheKey := r.cacheKeyFor("ui.greeting", sv, "vi")
	require.NoError(t, cache.SetNegative(ctx, cacheKey, time.Minute))

	got := r.Resolve(ctx, "ui.greeting", "vi")
	assert.Equal(t, "Xin chào", got, "seed value wins when cache is negative")
	assert.Zero(t, atomic.LoadInt64(&probe.calls), "DB must not be probed on cached-negative")
}

func TestResolve_CacheMissDbHitCachesAndReturnsOverride(t *testing.T) {
	seed := buildSeed(t)
	cache := newStubCache()
	probe := newStubProbe()
	r := buildRegistry(t, seed, probe, cache)
	ctx := context.Background()

	sv, _, _ := r.sourceVersionFor(ctx, "ui.greeting")
	probe.setHit("ui.greeting", sv, "vi", "Xin chào em!")

	got := r.Resolve(ctx, "ui.greeting", "vi")
	assert.Equal(t, "Xin chào em!", got)
	assert.Equal(t, int64(1), atomic.LoadInt64(&probe.calls))
	assert.Equal(t, int64(1), atomic.LoadInt64(&cache.setCalls), "positive hit must be cached")

	// Second call should be cached.
	got2 := r.Resolve(ctx, "ui.greeting", "vi")
	assert.Equal(t, "Xin chào em!", got2)
	assert.Equal(t, int64(1), atomic.LoadInt64(&probe.calls), "second call must not re-probe DB")
}

func TestResolve_CacheMissDbMissCachesNegativeAndReturnsSeed(t *testing.T) {
	seed := buildSeed(t)
	cache := newStubCache()
	probe := newStubProbe()
	r := buildRegistry(t, seed, probe, cache)
	ctx := context.Background()

	sv, _, _ := r.sourceVersionFor(ctx, "ui.greeting")
	probe.setMiss("ui.greeting", sv, "vi")

	got := r.Resolve(ctx, "ui.greeting", "vi")
	assert.Equal(t, "Xin chào", got)
	assert.Equal(t, int64(1), atomic.LoadInt64(&probe.calls))
	assert.Equal(t, int64(1), atomic.LoadInt64(&cache.setNegCalls), "miss must cache-negative")

	// Second call hits the cached-negative; no further DB probe.
	got2 := r.Resolve(ctx, "ui.greeting", "vi")
	assert.Equal(t, "Xin chào", got2)
	assert.Equal(t, int64(1), atomic.LoadInt64(&probe.calls))
}

func TestResolve_DbErrorDegradesToSeedAndCachesNegative(t *testing.T) {
	// DB error path: caller MUST get the seed value (graceful
	// degrade), and the error MUST cache-negative so we don't hammer
	// the DB during an outage.
	seed := buildSeed(t)
	cache := newStubCache()
	probe := newStubProbe()
	r := buildRegistry(t, seed, probe, cache)
	ctx := context.Background()

	sv, _, _ := r.sourceVersionFor(ctx, "ui.greeting")
	probe.setError("ui.greeting", sv, "vi", errors.New("connection refused"))

	got := r.Resolve(ctx, "ui.greeting", "vi")
	assert.Equal(t, "Xin chào", got)
	assert.Equal(t, int64(1), atomic.LoadInt64(&cache.setNegCalls))
}

func TestResolve_NoCacheStillWorks(t *testing.T) {
	// cache=nil — DynamicRegistry still functions, just hits the DB
	// on every Resolve. Useful for strict-consistency migration tools.
	seed := buildSeed(t)
	probe := newStubProbe()
	r := buildRegistry(t, seed, probe, nil)
	ctx := context.Background()

	sv, _, _ := r.sourceVersionFor(ctx, "ui.greeting")
	probe.setHit("ui.greeting", sv, "vi", "Override")

	got := r.Resolve(ctx, "ui.greeting", "vi")
	assert.Equal(t, "Override", got)
	got2 := r.Resolve(ctx, "ui.greeting", "vi")
	assert.Equal(t, "Override", got2)
	assert.Equal(t, int64(2), atomic.LoadInt64(&probe.calls), "no cache → every Resolve probes DB")
}

func TestResolve_SourceVersionIsMemoized(t *testing.T) {
	// sha256 hash + hex encode is cheap but it's per-Resolve. Memoize
	// after the first lookup so the hot path is a pure map read.
	seed := buildSeed(t)
	cache := newStubCache()
	probe := newStubProbe()
	r := buildRegistry(t, seed, probe, cache)
	ctx := context.Background()

	sv1, _, _ := r.sourceVersionFor(ctx, "ui.greeting")
	sv2, _, _ := r.sourceVersionFor(ctx, "ui.greeting")
	assert.Equal(t, sv1, sv2)

	// Memo populated:
	r.mu.RLock()
	cached := r.sourceVerMap["ui.greeting"]
	r.mu.RUnlock()
	assert.Equal(t, sv1, cached)
}

func TestResolve_SourceVersionDifferentEnglishSeedDifferentHash(t *testing.T) {
	// Same key, two different registries with different English text
	// → different source_version → DB lookup with the new sv finds
	// nothing for the stale override. Documents the "edit English →
	// stale overrides become invisible" semantics.
	seed1 := supportregistry.New([]string{"en", "vi"})
	require.True(t, seed1.Set("ui.greeting", "en", "Hello"))
	require.True(t, seed1.Set("ui.greeting", "vi", "Xin chào"))
	seed1.Finalize()
	r1 := New(seed1, nil, nil)
	sv1, _, _ := r1.sourceVersionFor(context.Background(), "ui.greeting")

	seed2 := supportregistry.New([]string{"en", "vi"})
	require.True(t, seed2.Set("ui.greeting", "en", "Hello there"))
	require.True(t, seed2.Set("ui.greeting", "vi", "Xin chào"))
	seed2.Finalize()
	r2 := New(seed2, nil, nil)
	sv2, _, _ := r2.sourceVersionFor(context.Background(), "ui.greeting")

	assert.NotEqual(t, sv1, sv2, "different English seed text must yield different source_version")
}

func TestResolveTemplate_AppliesParamsAfterOverride(t *testing.T) {
	// Override IS a template; ResolveTemplate must apply params to it.
	seed := supportregistry.New([]string{"en", "vi"})
	require.True(t, seed.Set("ui.welcome", "en", "Welcome {{.Name}}"))
	require.True(t, seed.Set("ui.welcome", "vi", "Chào {{.Name}}"))
	seed.Finalize()

	probe := newStubProbe()
	r := buildRegistry(t, seed, probe, newStubCache())
	sv, _, _ := r.sourceVersionFor(context.Background(), "ui.welcome")
	probe.setHit("ui.welcome", sv, "vi", "Xin chào {{.Name}}!")

	got := r.ResolveTemplate(context.Background(), "ui.welcome", "vi", map[string]any{"Name": "Khanh"})
	assert.Equal(t, "Xin chào Khanh!", got)
}

func TestResolveTemplate_NoOverrideAppliesParamsToSeed(t *testing.T) {
	seed := supportregistry.New([]string{"en", "vi"})
	require.True(t, seed.Set("ui.welcome", "en", "Welcome {{.Name}}"))
	require.True(t, seed.Set("ui.welcome", "vi", "Chào {{.Name}}"))
	seed.Finalize()

	probe := newStubProbe()
	r := buildRegistry(t, seed, probe, newStubCache())
	sv, _, _ := r.sourceVersionFor(context.Background(), "ui.welcome")
	probe.setMiss("ui.welcome", sv, "vi")

	got := r.ResolveTemplate(context.Background(), "ui.welcome", "vi", map[string]any{"Name": "Khanh"})
	assert.Equal(t, "Chào Khanh", got)
}

func TestSupportedLocales_PassThroughToSeed(t *testing.T) {
	seed := buildSeed(t)
	r := New(seed, nil, nil)
	assert.ElementsMatch(t, []string{"en", "vi", "sv"}, r.SupportedLocales())
}

// TestCoverageReport_PassThroughToSeed was superseded by
// TestCoverageReport_NoProbeReturnsSeedReportUnchanged below — the
// pilot-phase pass-through behavior is now reachable only via "pool
// nil" (no coverageProbe wired), which the newer test pins explicitly.

func TestNewWithCustomTTLs(t *testing.T) {
	seed := buildSeed(t)
	r := New(seed, nil, nil,
		WithHitTTL(10*time.Minute),
		WithMissTTL(1*time.Minute),
	)
	assert.Equal(t, 10*time.Minute, r.hitTTL)
	assert.Equal(t, time.Minute, r.missTTL)
}

func TestNewWithCustomResourceType(t *testing.T) {
	seed := buildSeed(t)
	r := New(seed, nil, nil, WithResourceType("custom.type"))
	assert.Equal(t, "custom.type", r.resType)
	assert.Equal(t, "dynreg:v1:custom.type:", r.keyPrefx)
}

func TestRedisCache_NoopBehaviour(t *testing.T) {
	// Smoke test for NoopCache + nil-receiver RedisCache.
	ctx := context.Background()

	var rc *RedisCache
	v, ov, ok := rc.Get(ctx, "k")
	assert.Empty(t, v)
	assert.False(t, ov)
	assert.False(t, ok)
	assert.NoError(t, rc.Set(ctx, "k", "v", time.Minute))
	assert.NoError(t, rc.SetNegative(ctx, "k", time.Minute))

	noop := NoopCache{}
	v, ov, ok = noop.Get(ctx, "k")
	assert.Empty(t, v)
	assert.False(t, ov)
	assert.False(t, ok)
	assert.NoError(t, noop.Set(ctx, "k", "v", time.Minute))
	assert.NoError(t, noop.SetNegative(ctx, "k", time.Minute))
}

func TestRegistry_StringDescription(t *testing.T) {
	// String is informational; just verify it includes the key knobs.
	seed := buildSeed(t)
	r := New(seed, nil, nil)
	s := r.String()
	assert.Contains(t, s, "dynamicregistry")
	assert.Contains(t, s, "no-pool")
	assert.Contains(t, s, "no-cache")
}

// ============================================================================
// CoverageReport.Overridden — DB-augmented per-locale counts
// ============================================================================

// stubCoverageProbe is a controllable coverageProbeFunc for tests.
type stubCoverageProbe struct {
	counts map[coverageKey]int
	err    error
	calls  int
}

func (s *stubCoverageProbe) probe(_ context.Context, _ string) (map[coverageKey]int, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.counts, nil
}

// warmKey forces a key into the source-version memo so collectSeedKeys
// will see it. Real production paths warm via Resolve traffic; tests
// short-circuit by calling sourceVersionFor directly. The returned
// triple is intentionally ignored — this is a memo-warmer, not a
// reader.
func warmKey(r *Registry, key supportregistry.Key) {
	//nolint:dogsled // memo-warmer; the triple is intentionally discarded
	_, _, _ = r.sourceVersionFor(context.Background(), key)
}

func TestCoverageReport_NoProbeReturnsSeedReportUnchanged(t *testing.T) {
	seed := buildSeed(t)
	r := New(seed, nil, nil) // pool nil → no coverageProbe wired
	got := r.CoverageReport()
	want := seed.CoverageReport()
	assert.Equal(t, want, got,
		"CoverageReport without a coverageProbe must pass the seed's report through")
}

func TestCoverageReport_OverriddenCountsBumpPerLocale(t *testing.T) {
	seed := buildSeed(t)
	r := newWithProbe(seed, nil)
	warmKey(r, "ui.greeting")
	warmKey(r, "ui.farewell")

	// Two override rows for vi, one for sv.
	stub := &stubCoverageProbe{
		counts: map[coverageKey]int{
			{resourceID: "ui.greeting", locale: "vi"}: 1,
			{resourceID: "ui.farewell", locale: "vi"}: 1,
			{resourceID: "ui.greeting", locale: "sv"}: 1,
		},
	}
	r.coverageProbe = stub.probe

	got := r.CoverageReport()
	require.Equal(t, 1, stub.calls, "exactly one aggregate query per CoverageReport call")
	assert.Equal(t, 2, got["vi"].Overridden, "vi should have 2 overridden keys")
	assert.Equal(t, 1, got["sv"].Overridden, "sv should have 1 overridden key")
	// en stays at 0 — Overridden tracks per-locale rows, and the
	// English seed IS the source-of-truth (no override possible).
	assert.Equal(t, 0, got["en"].Overridden, "en is the canonical source; Overridden stays 0")
}

func TestCoverageReport_IgnoresOverrideRowsForKeysNotInSeed(t *testing.T) {
	// Defensive: if a previous release had a key 'ui.deprecated' that
	// was removed in this release, override rows in the DB for that
	// key shouldn't inflate the per-locale Overridden count — those
	// rows are stale and the seam won't serve them anyway.
	seed := buildSeed(t)
	r := newWithProbe(seed, nil)
	warmKey(r, "ui.greeting")

	stub := &stubCoverageProbe{
		counts: map[coverageKey]int{
			{resourceID: "ui.greeting", locale: "vi"}:   1, // in seed
			{resourceID: "ui.deprecated", locale: "vi"}: 1, // NOT in seed → ignored
		},
	}
	r.coverageProbe = stub.probe

	got := r.CoverageReport()
	assert.Equal(t, 1, got["vi"].Overridden,
		"ui.deprecated has no seed entry; its override row must NOT count")
}

func TestCoverageReport_ProbeErrorDegradesToSeedReport(t *testing.T) {
	seed := buildSeed(t)
	r := newWithProbe(seed, nil)
	warmKey(r, "ui.greeting")

	stub := &stubCoverageProbe{err: errors.New("db down")}
	r.coverageProbe = stub.probe

	got := r.CoverageReport()
	want := seed.CoverageReport()
	assert.Equal(t, want, got,
		"probe error must fall through to seed's report; admin still sees Total/Localized/Fallback")
}

func TestCoverageReport_EmptyCountsReturnsSeedReport(t *testing.T) {
	// No override rows exist for this resource_type yet (fresh
	// install, empty table). Should be the seed report unchanged
	// (Overridden = 0 everywhere).
	seed := buildSeed(t)
	r := newWithProbe(seed, nil)
	warmKey(r, "ui.greeting")

	stub := &stubCoverageProbe{counts: map[coverageKey]int{}}
	r.coverageProbe = stub.probe

	got := r.CoverageReport()
	for locale, stats := range got {
		assert.Equalf(t, 0, stats.Overridden, "%s should have 0 overridden", locale)
	}
}
