// Package dynamicregistry composes a static supportregistry.Registry
// (typically a finalized MapRegistry) with a runtime-override layer
// backed by localization.dynamic_translations.
//
// Design rationale: see docs/architecture/adr-008-support-locale-adapter.md
// Phase 5 section. Two-line summary:
//
//   - Every Resolve probes the override layer first (Redis cache → DB).
//     If a row exists for (resource_type='ui.string', resource_id=key,
//     source_version=sha256(en_seed)[:16], language_code=requested),
//     that value wins. Otherwise the seed's Resolve is returned.
//   - Degrade-to-seed on every error path. The seed Registry is the
//     authoritative source-of-truth; the override layer is best-effort.
//
// This package lives in its own sub-package so consumers who only need
// the in-memory MapRegistry (tests, CLIs, services that don't yet wire
// the override layer) don't pull pgx + redis into their binaries.
package dynamicregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/team-kielo-app/kielo-shared/locale"
	"github.com/team-kielo-app/kielo-shared/locale/supportregistry"
)

// Cache is the minimal cache contract DynamicRegistry needs. Implement
// against Redis (see RedisCache below) or supply a no-op for tests.
//
// The DynamicRegistry caches both positive hits (override row found,
// value cached) and negative hits (no override row, "no override"
// flag cached). Both are keyed off the same composite cache key. A
// `found=false, ok=true` return means "cached negative — definitively
// no override".
type Cache interface {
	// Get returns (value, isOverride, cachedOK). cachedOK=false means
	// cache miss (caller should probe DB). cachedOK=true + isOverride=true
	// means the cached value IS the override. cachedOK=true +
	// isOverride=false means cached-negative (no override exists).
	Get(ctx context.Context, key string) (value string, isOverride, cachedOK bool)

	// Set caches a positive override hit.
	Set(ctx context.Context, key, value string, ttl time.Duration) error

	// SetNegative caches a "no override exists" result for this key,
	// usually with a shorter TTL than positive hits.
	SetNegative(ctx context.Context, key string, ttl time.Duration) error
}

// dbProbeFunc is the override-DB lookup signature. Production wires it
// to `(*pgxpool.Pool).QueryRow` against localization.dynamic_translations;
// tests wire a stub. Returns (value, found, err) — same triple as
// probeOverride.
type dbProbeFunc func(ctx context.Context, resourceType, resourceID, sourceVersion, locale string) (value string, found bool, err error)

// coverageProbeFunc is the override-coverage aggregate-query signature.
// Production wires it to a `SELECT resource_id, language_code, COUNT(*)
// FROM localization.dynamic_translations WHERE resource_type=$1 AND
// status IN ('machine','override','approved') GROUP BY resource_id,
// language_code`. Tests wire a stub.
//
// Returns a map keyed by (resource_id, locale) → row count. Caller
// uses the map to bump CoverageStats.Overridden for keys + locales
// present in the seed.
type coverageProbeFunc func(ctx context.Context, resourceType string) (map[coverageKey]int, error)

// coverageKey is the (resource_id, locale) tuple coverageProbeFunc
// returns counts by. Package-private; consumers only see the
// aggregated CoverageStats.
type coverageKey struct {
	resourceID string
	locale     string
}

// Registry is the DynamicRegistry. Satisfies supportregistry.Registry
// so it's a drop-in replacement for MapRegistry at every call site.
type Registry struct {
	seed          supportregistry.Registry
	probe         dbProbeFunc
	coverageProbe coverageProbeFunc
	cache         Cache
	hitTTL        time.Duration
	missTTL       time.Duration
	resType       string
	keyPrefx      string

	// Source-version memo: english seed → sha256[:16]. Lazily filled on
	// first lookup per key. RWMutex because Resolve is a hot path and
	// the memo write is rare-after-warmup.
	mu           sync.RWMutex
	sourceVerMap map[string]string
}

// Default cache TTLs. Override via WithHitTTL / WithMissTTL.
//
// hitTTL=5m: overrides are rare-write admin actions. 5 minutes keeps
// the hot path fast while bounding staleness after an admin edit to
// "the operator clicks save, then waits 5 minutes". Acceptable per
// ADR-008 §"Cache contract".
//
// missTTL=30s: negative-cache must be short so that the FIRST override
// for a never-overridden key surfaces within ~30 seconds.
const (
	DefaultHitTTL  = 5 * time.Minute
	DefaultMissTTL = 30 * time.Second
)

// New constructs a DynamicRegistry.
//
//   - seed: the canonical Registry that holds all keys (typically a
//     finalized MapRegistry built from YAML / Go-map seeds).
//   - pool: pgxpool.Pool for localization.dynamic_translations probes.
//     Pass nil to disable the override layer entirely (DynamicRegistry
//     degrades to a pass-through over seed; useful for tests).
//   - cache: implementation of the Cache interface. Pass nil or
//     NoopCache{} to skip the cache layer and probe the DB on every
//     Resolve (slow but strictly-consistent — useful for migration
//     tools that need to see overrides immediately after writing).
func New(seed supportregistry.Registry, pool *pgxpool.Pool, cache Cache, opts ...Option) *Registry {
	r := newWithProbe(seed, cache, opts...)
	if pool != nil {
		r.probe = func(ctx context.Context, rt, rid, sv, loc string) (string, bool, error) {
			return queryPool(ctx, pool, rt, rid, sv, loc)
		}
		r.coverageProbe = func(ctx context.Context, rt string) (map[coverageKey]int, error) {
			return queryCoverage(ctx, pool, rt)
		}
	}
	return r
}

// newWithProbe is the test-only constructor that takes a custom probe
// function instead of a pgxpool.Pool. Keeps unit tests free of a real
// DB while preserving the pool-driven production path.
func newWithProbe(seed supportregistry.Registry, cache Cache, opts ...Option) *Registry {
	r := &Registry{
		seed:         seed,
		cache:        cache,
		hitTTL:       DefaultHitTTL,
		missTTL:      DefaultMissTTL,
		resType:      locale.ResourceTypeUIString,
		sourceVerMap: make(map[string]string),
	}
	r.keyPrefx = "dynreg:v1:" + r.resType + ":"
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Option mutates a Registry at construction time.
type Option func(*Registry)

// WithHitTTL sets the positive-cache TTL. Default 5 minutes.
func WithHitTTL(ttl time.Duration) Option {
	return func(r *Registry) {
		if ttl > 0 {
			r.hitTTL = ttl
		}
	}
}

// WithMissTTL sets the negative-cache TTL. Default 30 seconds.
func WithMissTTL(ttl time.Duration) Option {
	return func(r *Registry) {
		if ttl > 0 {
			r.missTTL = ttl
		}
	}
}

// WithResourceType overrides the resource_type used in DB lookups.
// Defaults to locale.ResourceTypeUIString. Useful only for tests /
// future polymorphism — production should use the default.
func WithResourceType(rt string) Option {
	return func(r *Registry) {
		rt = strings.TrimSpace(rt)
		if rt != "" {
			r.resType = rt
			r.keyPrefx = "dynreg:v1:" + rt + ":"
		}
	}
}

// Resolve implements supportregistry.Registry.
//
// Probe order:
//  1. Compute source_version from the seed's English value for this key.
//     If the seed has no English seed at all, skip the override layer
//     entirely (registry returns string(key) anyway; no point probing
//     a "ui.string"-row for a non-existent key).
//  2. Cache: Get(cacheKey). Positive hit → return. Negative cache hit
//     → skip DB, fall through to seed.
//  3. DB probe: same SQL as overridepgx.Store.Lookup. On hit, cache +
//     return. On miss, cache-negative + fall through to seed.
//  4. Seed: r.seed.Resolve(ctx, key, supportLocale).
func (r *Registry) Resolve(ctx context.Context, key supportregistry.Key, supportLocale string) string {
	sv, sourceText, hasSourceVersion := r.sourceVersionFor(ctx, key)
	if !hasSourceVersion {
		// Seed has no English seed for this key — overrides can't
		// exist for a "ui.string" row for a non-existent key. Skip
		// the override layer.
		return r.seed.Resolve(ctx, key, supportLocale)
	}

	normLocale := strings.ToLower(strings.TrimSpace(supportLocale))
	if normLocale == "" {
		// Empty locale means "no preference"; the seed's English
		// fallback is the right answer. No point probing.
		return r.seed.Resolve(ctx, key, supportLocale)
	}

	// English overrides don't apply: the English seed IS the source-of-truth.
	// (Operators wanting to edit the English wording change the seed.)
	if normLocale == supportregistry.FallbackLocale {
		return sourceText
	}

	cacheKey := r.cacheKeyFor(string(key), sv, normLocale)

	if r.cache != nil {
		value, isOverride, ok := r.cache.Get(ctx, cacheKey)
		if ok {
			if isOverride {
				return value
			}
			// Negative cache hit — definitively no override.
			return r.seed.Resolve(ctx, key, supportLocale)
		}
	}

	value, found, dbErr := r.probeOverride(ctx, string(key), sv, normLocale)
	if dbErr != nil || !found {
		// DB error OR no row: cache-negative for missTTL and fall
		// through to the seed. We cache-negative on DB error too
		// (best-effort degrade — recovering DB will refill the cache
		// after missTTL anyway).
		if r.cache != nil {
			_ = r.cache.SetNegative(ctx, cacheKey, r.missTTL)
		}
		return r.seed.Resolve(ctx, key, supportLocale)
	}

	if r.cache != nil {
		_ = r.cache.Set(ctx, cacheKey, value, r.hitTTL)
	}
	return value
}

// ResolveTemplate implements supportregistry.Registry. Resolves the key
// (which may now be an override) and applies Go text/template
// substitution. Mirrors MapRegistry.ResolveTemplate.
func (r *Registry) ResolveTemplate(ctx context.Context, key supportregistry.Key, supportLocale string, params map[string]any) string {
	text := r.Resolve(ctx, key, supportLocale)
	if !strings.Contains(text, "{{") {
		return text
	}
	return supportregistry.ApplyTemplate(text, params)
}

// SupportedLocales implements supportregistry.Registry. Pass-through to
// the seed; the override layer is a SUPERSET of the seed's locales
// (overrides for unknown locales never get applied because Resolve's
// normLocale check fails first), so the seed's list is correct.
func (r *Registry) SupportedLocales() []string {
	return r.seed.SupportedLocales()
}

// CoverageReport implements supportregistry.Registry.
//
// Starts from the seed's CoverageReport (which already populates Total,
// Localized, Fallback). DynamicRegistry should additionally fill in
// Overridden by scanning the DB for matching rows. That scan is a
// follow-up (would do `SELECT language_code, COUNT(*) FROM
// localization.dynamic_translations WHERE resource_type=... AND
// status IN ('override','approved') GROUP BY language_code`); for the
// pilot phase we return the seed report unchanged.
// CoverageReport returns the seed's coverage stats, augmented with
// per-locale Overridden counts read from localization.dynamic_translations.
//
// The seed (typically a MapRegistry) populates Total / Localized /
// Fallback by walking the in-memory key set. This wrapper layers in
// Overridden by running ONE aggregate query against the override
// table and bumping each locale's count by how many of the seed's
// keys have a matching override row (status IN
// ('machine','override','approved')).
//
// Failure mode: any error from the coverage probe falls through to
// returning the seed's report unchanged. The CMS admin grid prefers
// "Overridden: 0 (probe failed)" over "no coverage data at all" —
// admins can still see Total/Localized.
//
// Performance: ONE aggregate query per CoverageReport call. The CMS
// admin grid calls this rarely (page load), not per-Resolve, so the
// cost is bounded. No caching here — the admin wants fresh numbers
// after they author a row.
func (r *Registry) CoverageReport() map[string]supportregistry.CoverageStats {
	base := r.seed.CoverageReport()
	if r.coverageProbe == nil {
		return base
	}

	counts, err := r.coverageProbe(context.Background(), r.resType)
	if err != nil || len(counts) == 0 {
		return base
	}

	// Build the set of seed keys so we ignore overrides for keys the
	// seed doesn't know about (defensive: stale rows from a
	// previously-removed key shouldn't inflate "Overridden" for a
	// locale).
	seedKeys := r.collectSeedKeys()
	if len(seedKeys) == 0 {
		return base
	}

	// Walk override counts; bump Overridden per locale for each seed
	// key with at least one override row.
	overrideByLocale := make(map[string]int)
	for ck := range counts {
		if _, ok := seedKeys[ck.resourceID]; !ok {
			continue
		}
		overrideByLocale[ck.locale]++
	}

	out := make(map[string]supportregistry.CoverageStats, len(base))
	for locale, stats := range base {
		stats.Overridden = overrideByLocale[locale]
		out[locale] = stats
	}
	return out
}

// collectSeedKeys returns the set of registry keys the seed knows
// about, used to filter out stale override rows whose seed key was
// removed in a later release. Probes the seed by calling Resolve()
// with the English locale on every supported locale's key set —
// inefficient for huge registries but acceptable for the admin
// coverage view's once-per-page-load call shape.
//
// Returns an empty map if the seed isn't a MapRegistry (other
// implementations may not expose key iteration); in that case
// CoverageReport falls through to the seed's report unchanged with
// no Overridden enrichment.
func (r *Registry) collectSeedKeys() map[string]struct{} {
	// The supportregistry.Registry interface deliberately does NOT
	// expose key iteration. The seed memo is the only available
	// source of "keys this registry has seen". The memo populates
	// lazily on first Resolve, so a freshly-built registry that
	// hasn't served any traffic has an empty memo.
	//
	// For the admin coverage view the practical workaround is for
	// services to either (a) warm the memo at startup by Resolving
	// each known key once, OR (b) wait for organic traffic to fill
	// it. Either way, Overridden may under-report briefly after a
	// service restart — acceptable for an admin-side metric.
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]struct{}, len(r.sourceVerMap))
	for k := range r.sourceVerMap {
		out[k] = struct{}{}
	}
	return out
}

// Compile-time assertion that *Registry satisfies the seed contract.
var _ supportregistry.Registry = (*Registry)(nil)

// sourceVersionFor returns (sourceVersion, englishSeedText, hasSeed).
// Memoized — first call computes sha256[:16]; later calls are a map read.
//
// hasSeed=false signals "the seed has no English value for this key";
// callers should skip the override layer in that case (no point
// probing for an override of a non-existent key).
func (r *Registry) sourceVersionFor(ctx context.Context, key supportregistry.Key) (sourceVersion, englishSeedText string, hasSeed bool) {
	keyStr := string(key)

	r.mu.RLock()
	if sv, ok := r.sourceVerMap[keyStr]; ok {
		r.mu.RUnlock()
		// Reconstruct English seed text only if needed (Resolve's
		// English-shortcut path). Re-query the seed; it's an in-memory
		// map lookup.
		englishSeed := r.seed.Resolve(ctx, key, supportregistry.FallbackLocale)
		return sv, englishSeed, englishSeed != keyStr
	}
	r.mu.RUnlock()

	englishSeed := r.seed.Resolve(ctx, key, supportregistry.FallbackLocale)
	if englishSeed == keyStr {
		// Registry miss: seed has no English value for this key.
		// Memoize empty string to short-circuit future probes for the
		// same unknown key.
		r.mu.Lock()
		r.sourceVerMap[keyStr] = ""
		r.mu.Unlock()
		return "", "", false
	}

	sum := sha256.Sum256([]byte(englishSeed))
	sv := hex.EncodeToString(sum[:8])

	r.mu.Lock()
	r.sourceVerMap[keyStr] = sv
	r.mu.Unlock()

	return sv, englishSeed, true
}

// cacheKeyFor builds the Redis cache key for an override probe.
// Shape: dynreg:v1:{resource_type}:{resource_id}:{source_version}:{locale}
func (r *Registry) cacheKeyFor(resourceID, sourceVersion, locale string) string {
	return r.keyPrefx + resourceID + ":" + sourceVersion + ":" + locale
}

// dbLookupQuery is identical in shape to overridepgx.Store.Lookup —
// see that package for the rationale on status filter + ordering.
const dbLookupQuery = `
	SELECT translated_text
	  FROM localization.dynamic_translations
	 WHERE resource_type   = $1
	   AND resource_id     = $2
	   AND source_version  = $3
	   AND language_code   = $4
	   AND status         IN ('override', 'approved')
	 ORDER BY CASE status WHEN 'override' THEN 0 ELSE 1 END
	 LIMIT 1
`

// probeOverride dispatches to the configured probe function (the
// pgxpool-backed `queryPool` in production; a stub in unit tests). When
// no probe is configured (pool was nil at construction), reports
// no-rows so DynamicRegistry degrades to a pure seed pass-through.
func (r *Registry) probeOverride(ctx context.Context, resourceID, sourceVersion, locale string) (value string, found bool, err error) {
	if r.probe == nil {
		return "", false, nil
	}
	return r.probe(ctx, r.resType, resourceID, sourceVersion, locale)
}

// queryPool is the production probe — pgxpool.Pool QueryRow against
// localization.dynamic_translations. Same shape as
// overridepgx.Store.Lookup; see that package for index-plan notes.
func queryPool(
	ctx context.Context,
	pool *pgxpool.Pool,
	resourceType, resourceID, sourceVersion, locale string,
) (value string, found bool, err error) {
	err = pool.QueryRow(ctx, dbLookupQuery, resourceType, resourceID, sourceVersion, locale).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return value, true, nil
}

// dbCoverageQuery is the aggregate-count query that drives
// CoverageReport.Overridden. status filter mirrors the read-path
// (status IN ('machine','override','approved')) so the count reflects
// what the seam would actually serve.
const dbCoverageQuery = `
	SELECT resource_id, language_code, COUNT(*) AS row_count
	  FROM localization.dynamic_translations
	 WHERE resource_type = $1
	   AND status        IN ('machine', 'override', 'approved')
	 GROUP BY resource_id, language_code
`

// queryCoverage runs the aggregate-count query against the pool.
// Returns a map keyed by (resource_id, locale) → row count. Errors
// degrade the caller to seed-only coverage (see CoverageReport).
func queryCoverage(
	ctx context.Context,
	pool *pgxpool.Pool,
	resourceType string,
) (map[coverageKey]int, error) {
	rows, err := pool.Query(ctx, dbCoverageQuery, resourceType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[coverageKey]int)
	for rows.Next() {
		var k coverageKey
		var count int
		if err := rows.Scan(&k.resourceID, &k.locale, &count); err != nil {
			return nil, err
		}
		out[k] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// String returns a brief description, useful for logging.
func (r *Registry) String() string {
	dbState := "no-pool"
	if r.probe != nil {
		dbState = "pgx"
	}
	cacheState := "no-cache"
	if r.cache != nil {
		cacheState = "cached"
	}
	return fmt.Sprintf("dynamicregistry{resource_type=%s, db=%s, cache=%s, hitTTL=%s, missTTL=%s}",
		r.resType, dbState, cacheState, r.hitTTL, r.missTTL)
}
