package localization

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Seam is the high-level translation entry point per ADR-007. Callers
// hand it a canonical English string and a target locale; the seam
// resolves through override-table → Redis cache → provider in that
// order, with single-flight protection on cache misses and
// stale-while-revalidate on hot keys.
//
// Construction: callers wire dependencies via NewSeam, passing concrete
// implementations of Cache / OverrideStore / Metrics or the Noop
// variants for environments that aren't ready for the full stack. The
// Registry comes from the existing provider routing layer.
//
// English is always a no-op pass-through: the seam never invokes a
// provider for target="en" and never persists English to the cache or
// override table. This keeps the common case zero-latency.
type Seam struct {
	registry  *Registry
	cache     Cache
	overrides OverrideStore
	metrics   Metrics
	group     singleflight.Group

	// freshTTL is how long cached values are considered fresh.
	// Lookups within this window are served straight from cache.
	freshTTL time.Duration
	// staleTTL is the additional window during which stale cached
	// values are served immediately while a background refresh runs
	// (stale-while-revalidate). Total cache lifetime is freshTTL +
	// staleTTL.
	staleTTL time.Duration

	// swrInFlight tracks background refreshes started for SWR hits so
	// concurrent stale reads don't each kick off a refresh.
	swrInFlight sync.Map // map[string]struct{}
}

// SeamConfig carries optional knobs. Zero-value fields use defaults
// that match production expectations for content translations.
type SeamConfig struct {
	// FreshTTL defaults to 24h. Cached translations are served straight
	// from cache for this duration.
	FreshTTL time.Duration
	// StaleTTL defaults to 6 days. After FreshTTL expires, the cached
	// value is still served but a background refresh runs.
	StaleTTL time.Duration
}

// NewSeam constructs a Seam. Pass Noop* implementations for any
// dependency that isn't wired yet — the seam still functions, just
// without caching / overrides / telemetry coverage.
func NewSeam(registry *Registry, cache Cache, overrides OverrideStore, metrics Metrics, cfg SeamConfig) *Seam {
	if cfg.FreshTTL <= 0 {
		cfg.FreshTTL = 24 * time.Hour
	}
	if cfg.StaleTTL <= 0 {
		cfg.StaleTTL = 6 * 24 * time.Hour
	}
	if cache == nil {
		cache = NoopCache{}
	}
	if overrides == nil {
		overrides = NoopOverrideStore{}
	}
	if metrics == nil {
		metrics = NoopMetrics{}
	}
	return &Seam{
		registry:  registry,
		cache:     cache,
		overrides: overrides,
		metrics:   metrics,
		freshTTL:  cfg.FreshTTL,
		staleTTL:  cfg.StaleTTL,
	}
}

// SourceRef identifies a unique translatable string by namespace +
// source id + source version. Same (namespace, sourceID, sourceVersion)
// across two requests means the same canonical English text.
//
// SourceVersion is the cache-busting key. When an author edits the
// canonical English source, callers must bump SourceVersion (typically
// by hashing source_text + updated_at) so stale translations from
// before the edit become unreachable.
type SourceRef struct {
	// Namespace is the content-kind identifier. Examples:
	// "convo.scenario.title", "convo.scenario.description",
	// "convo.eval.feedback", "dictionary.gloss". Used both for routing
	// (per-namespace TTL tuning) and for telemetry slicing.
	Namespace string
	// SourceID identifies the specific source row. For scenario titles
	// it's the scenario UUID; for dictionary glosses it's the entry id.
	SourceID string
	// SourceVersion is a stable hash of the canonical source text +
	// any other inputs that should bust the cache on change (typically
	// updated_at). Callers should use SourceVersionFromText to compute
	// this consistently.
	SourceVersion string
	// SourceText is the canonical English string to translate. Never
	// empty for live calls.
	SourceText string
	// Role hints the provider at prompt selection / output validation.
	// Defaults to RolePlain.
	Role TranslationRole
}

// SourceVersionFromText derives a stable cache-key suffix from the
// source text alone. Callers that want updated_at-based busting should
// pass `text + "|" + updated_at.Format(time.RFC3339)` and use the
// returned hex. The hash is truncated to 16 hex chars (8 bytes) — plenty
// for collision-resistance within a namespace and small enough for
// cache keys.
func SourceVersionFromText(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{'|'})
		}
		h.Write([]byte(p))
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// Translate resolves the source ref to a localized string in
// targetLocale. Never returns an empty string for non-empty SourceText —
// on every error path the seam falls back to SourceText (English) to
// guarantee the UI always has something to render.
//
// Telemetry: every call records exactly one
// `kielo_translation_total{namespace, target_locale, source}` increment
// where source is one of english_passthrough, override, cache_hit,
// cache_swr, cache_miss_share, provider_call, provider_error.
//
// Sweep TTTT-I: also bumps the per-request budget counter (when
// WithBudget was called on ctx) so middleware can stamp response
// headers + dashboards can detect N+1 fan-outs.
func (s *Seam) Translate(ctx context.Context, ref SourceRef, targetLocale string) string {
	source, value := s.resolve(ctx, ref, targetLocale)
	s.metrics.Record(ctx, ref.Namespace, targetLocale, source)
	RecordBudget(ctx, BudgetKindRefResolved, 1)
	switch source {
	case "override":
		RecordBudget(ctx, BudgetKindOverrideLookup, 1)
	case "cache_hit", "cache_swr":
		RecordBudget(ctx, BudgetKindCacheGet, 1)
	case "provider_call", "cache_miss_share":
		// Override+cache miss path: 1 override probe + 1 cache probe
		// + 1 provider call.
		RecordBudget(ctx, BudgetKindOverrideLookup, 1)
		RecordBudget(ctx, BudgetKindCacheGet, 1)
		RecordBudget(ctx, BudgetKindProviderCall, 1)
	}
	return value
}

// TranslateBatch resolves multiple refs to the same target locale in
// one call. Sweep TTTT-B: TRUE batch path — one composite-tuple SQL
// query for overrides, one Redis MGET for cache, one provider batch
// call for misses. Pre-TTTT this method was a fake loop over Translate
// which produced N sequential DB+Redis+provider RTTs for N refs.
//
// Telemetry: per-item metrics still emitted (one counter per ref) so
// the per-namespace breakdown survives the batch consolidation.
//
// Fallback behavior: when the configured Cache/OverrideStore don't
// implement the batch interfaces (BatchCache / BatchOverrideStore),
// this method degrades gracefully to per-ref Translate. Production
// deployments wire RedisCache + pgx OverrideStore which both
// implement the batch interfaces, so the fast path is the norm.
//
//nolint:funlen // Batch seam keeps cache, override, provider, and metrics branches together for one round-trip contract.
func (s *Seam) TranslateBatch(ctx context.Context, refs []SourceRef, targetLocale string) []string {
	out := make([]string, len(refs))
	if len(refs) == 0 {
		return out
	}

	// Short-circuit empty / English / source-text-empty cases per-ref
	// without touching the backing stores. Build the residue slice of
	// refs that genuinely need resolution.
	target := strings.TrimSpace(strings.ToLower(targetLocale))
	residue := make([]residueEntry, 0, len(refs))
	for i, ref := range refs {
		if strings.TrimSpace(ref.SourceText) == "" {
			out[i] = ""
			s.metrics.Record(ctx, ref.Namespace, target, "english_passthrough")
			continue
		}
		if target == "" || target == TierASupportLocale {
			out[i] = ref.SourceText
			s.metrics.Record(ctx, ref.Namespace, target, "english_passthrough")
			continue
		}
		residue = append(residue, residueEntry{
			idx: i,
			ref: ref,
			key: s.cacheKey(ref, target),
		})
	}
	if len(residue) == 0 {
		return out
	}

	// Sweep TTTT-I: count total refs resolved for the budget snapshot.
	RecordBudget(ctx, BudgetKindRefResolved, len(refs))

	// Phase 1: batch override lookup. One SQL round-trip when impl
	// supports BatchOverrideStore; fallback to per-ref Lookup otherwise.
	RecordBudget(ctx, BudgetKindOverrideLookup, 1)
	overrideHits := s.batchOverrideLookup(ctx, residue, target)
	remaining := residue[:0]
	for _, r := range residue {
		batchKey := OverrideBatchKey(r.ref.Namespace, r.ref.SourceID, r.ref.SourceVersion)
		if val, ok := overrideHits[batchKey]; ok {
			out[r.idx] = val
			s.metrics.Record(ctx, r.ref.Namespace, target, "override")
			continue
		}
		remaining = append(remaining, r)
	}
	if len(remaining) == 0 {
		return out
	}

	// Phase 2: batch cache lookup. One Redis MGET pipeline when impl
	// supports BatchCache; fallback to per-ref Get otherwise.
	RecordBudget(ctx, BudgetKindCacheGet, 1)
	cacheHits := s.batchCacheGet(ctx, remaining)
	remaining2 := remaining[:0]
	for _, r := range remaining {
		entry, ok := cacheHits[r.key]
		if !ok {
			remaining2 = append(remaining2, r)
			continue
		}
		if entry.Age <= s.freshTTL {
			out[r.idx] = entry.Value
			s.metrics.Record(ctx, r.ref.Namespace, target, "cache_hit")
			continue
		}
		if entry.Age <= s.freshTTL+s.staleTTL {
			s.kickoffSWR(ctx, r.ref, target, r.key)
			out[r.idx] = entry.Value
			s.metrics.Record(ctx, r.ref.Namespace, target, "cache_swr")
			continue
		}
		remaining2 = append(remaining2, r)
	}
	if len(remaining2) == 0 {
		return out
	}

	// Phase 3: provider batch call for cache misses. Single round-trip
	// to the LLM / opus-mt regardless of len(remaining2). Per-ref
	// single-flight via singleflight.Group preserves the dedup
	// behavior — if two concurrent batch requests overlap on the same
	// cache key, only one provider call fires.
	RecordBudget(ctx, BudgetKindProviderCall, 1)
	s.providerBatchCall(ctx, remaining2, target, out)
	return out
}

// residueEntry is the in-flight bookkeeping shape used by
// TranslateBatch + the per-phase batch helpers. Keeps the (idx, ref,
// cacheKey) triple coherent through override → cache → provider phases.
type residueEntry struct {
	idx int
	ref SourceRef
	key string // cache key
}

// batchOverrideLookup issues either one BatchOverrideStore.BatchLookup
// call (fast path) or len(residue) sequential Lookup calls (fallback).
func (s *Seam) batchOverrideLookup(
	ctx context.Context,
	residue []residueEntry,
	target string,
) map[string]string {
	if batchStore, ok := s.overrides.(BatchOverrideStore); ok {
		refs := make([]OverrideRef, len(residue))
		for i, r := range residue {
			refs[i] = OverrideRef{
				Namespace:     r.ref.Namespace,
				SourceID:      r.ref.SourceID,
				SourceVersion: r.ref.SourceVersion,
			}
		}
		hits, err := batchStore.BatchLookup(ctx, refs, target)
		if err == nil {
			return hits
		}
		// Fall through to per-ref fallback on error so a transient
		// DB issue doesn't blow up the whole request.
	}
	hits := make(map[string]string, len(residue))
	for _, r := range residue {
		if val, ok := s.overrides.Lookup(ctx, r.ref.Namespace, r.ref.SourceID, r.ref.SourceVersion, target); ok {
			hits[OverrideBatchKey(r.ref.Namespace, r.ref.SourceID, r.ref.SourceVersion)] = val
		}
	}
	return hits
}

// batchCacheGet issues either one BatchCache.BatchGet (fast path) or
// len(remaining) sequential Get calls (fallback).
func (s *Seam) batchCacheGet(
	ctx context.Context,
	remaining []residueEntry,
) map[string]CacheEntry {
	if batchCache, ok := s.cache.(BatchCache); ok {
		keys := make([]string, len(remaining))
		for i, r := range remaining {
			keys[i] = r.key
		}
		return batchCache.BatchGet(ctx, keys)
	}
	hits := make(map[string]CacheEntry, len(remaining))
	for _, r := range remaining {
		if entry, ok := s.cache.Get(ctx, r.key); ok {
			hits[r.key] = entry
		}
	}
	return hits
}

// providerBatchCall issues one provider.TranslateBatch for all
// cache-miss refs, then persists results to cache via BatchSet (when
// supported) or per-key Set fallback. Records per-ref metrics.
func (s *Seam) providerBatchCall(
	ctx context.Context,
	remaining []residueEntry,
	target string,
	out []string,
) {
	provider, err := s.registry.Resolve(TierASupportLocale, target)
	if err != nil {
		for _, r := range remaining {
			out[r.idx] = r.ref.SourceText
			s.metrics.Record(ctx, r.ref.Namespace, target, "provider_error")
		}
		return
	}

	// Build the provider items + use singleflight per ref so concurrent
	// requests for the same cache key dedup. The shared/owner split
	// here mirrors the single-Translate behavior so metrics stay
	// faithful.
	items := make([]TranslationItem, len(remaining))
	for i, r := range remaining {
		role := r.ref.Role
		if role == "" {
			role = RolePlain
		}
		items[i] = TranslationItem{
			Text:     r.ref.SourceText,
			Role:     role,
			CacheKey: r.key,
		}
	}
	results, err := provider.TranslateBatch(ctx, items, TranslateOptions{
		SourceLocale: TierASupportLocale,
		TargetLocale: target,
	})
	if err != nil || len(results) != len(remaining) {
		for _, r := range remaining {
			out[r.idx] = r.ref.SourceText
			s.metrics.Record(ctx, r.ref.Namespace, target, "provider_error")
		}
		return
	}

	// Persist + assign. Build a write-set for BatchSet when available.
	writeSet := make(map[string]string, len(remaining))
	for i, r := range remaining {
		value := strings.TrimSpace(results[i].Text)
		if value == "" {
			out[r.idx] = r.ref.SourceText
			s.metrics.Record(ctx, r.ref.Namespace, target, "provider_error")
			continue
		}
		out[r.idx] = value
		writeSet[r.key] = value
		s.metrics.Record(ctx, r.ref.Namespace, target, "provider_call")
	}
	if len(writeSet) > 0 {
		if batchCache, ok := s.cache.(BatchCache); ok {
			_ = batchCache.BatchSet(ctx, writeSet, s.freshTTL+s.staleTTL)
		} else {
			for k, v := range writeSet {
				_ = s.cache.Set(ctx, k, v, s.freshTTL+s.staleTTL)
			}
		}
	}
}

// resolve runs the resolution chain and returns (telemetry-source-tag, value).
func (s *Seam) resolve(ctx context.Context, ref SourceRef, targetLocale string) (sourceTag, value string) {
	if strings.TrimSpace(ref.SourceText) == "" {
		return "english_passthrough", ""
	}
	target := strings.TrimSpace(strings.ToLower(targetLocale))
	if target == "" || target == TierASupportLocale {
		return "english_passthrough", ref.SourceText
	}

	if value, ok := s.overrides.Lookup(ctx, ref.Namespace, ref.SourceID, ref.SourceVersion, target); ok {
		return "override", value
	}

	cacheKey := s.cacheKey(ref, target)
	if entry, ok := s.cache.Get(ctx, cacheKey); ok {
		if entry.Age <= s.freshTTL {
			return "cache_hit", entry.Value
		}
		if entry.Age <= s.freshTTL+s.staleTTL {
			s.kickoffSWR(ctx, ref, target, cacheKey)
			return "cache_swr", entry.Value
		}
	}

	raw, _, shared := s.group.Do(cacheKey, func() (any, error) {
		return s.callProvider(ctx, ref, target, cacheKey), nil
	})
	rendered, _ := raw.(string)
	if shared {
		return "cache_miss_share", rendered
	}
	return "provider_call", rendered
}

// kickoffSWR launches a background refresh for a stale cache hit if no
// other refresh is already in flight for this key. Uses sync.Map as a
// lock-free set; LoadOrStore guarantees only the first caller starts a
// refresh.
func (s *Seam) kickoffSWR(ctx context.Context, ref SourceRef, target, cacheKey string) {
	if _, loaded := s.swrInFlight.LoadOrStore(cacheKey, struct{}{}); loaded {
		return
	}
	go func() {
		defer s.swrInFlight.Delete(cacheKey)
		bgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		s.callProvider(bgCtx, ref, target, cacheKey)
	}()
}

// callProvider routes through the registry, persists the result to
// cache, and returns the translated value. On any provider error or
// empty result, returns SourceText so the UI never renders blank.
func (s *Seam) callProvider(ctx context.Context, ref SourceRef, target, cacheKey string) string {
	provider, err := s.registry.Resolve(TierASupportLocale, target)
	if err != nil {
		s.metrics.Record(ctx, ref.Namespace, target, "provider_error")
		return ref.SourceText
	}
	role := ref.Role
	if role == "" {
		role = RolePlain
	}
	items := []TranslationItem{{
		Text:     ref.SourceText,
		Role:     role,
		CacheKey: cacheKey,
	}}
	results, err := provider.TranslateBatch(ctx, items, TranslateOptions{
		SourceLocale: TierASupportLocale,
		TargetLocale: target,
	})
	if err != nil || len(results) == 0 {
		s.metrics.Record(ctx, ref.Namespace, target, "provider_error")
		return ref.SourceText
	}
	value := strings.TrimSpace(results[0].Text)
	if value == "" {
		s.metrics.Record(ctx, ref.Namespace, target, "provider_error")
		return ref.SourceText
	}
	_ = s.cache.Set(ctx, cacheKey, value, s.freshTTL+s.staleTTL)
	return value
}

func (s *Seam) cacheKey(ref SourceRef, target string) string {
	return fmt.Sprintf("kielo:i18n:%s:%s:%s:%s", ref.Namespace, ref.SourceID, ref.SourceVersion, target)
}

// TierASupportLocale is the canonical English code per ADR-007. Lives
// here rather than referencing kielo-shared/locale to avoid a circular
// dependency (locale imports nothing; localization imports nothing
// app-specific). Keep in sync with locale.TierASupportLocale.
const TierASupportLocale = "en"
