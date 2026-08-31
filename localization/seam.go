package localization

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	safego "github.com/team-kielo-app/kielo-shared/observe/safego"
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
	// persister is the seam's write-through to
	// localization.dynamic_translations. Round 10D. Default
	// NoopPersister preserves pre-Round-10D cache-only behavior.
	persister TranslationPersister
	// guard rejects suspicious provider output. Round 10D. Default
	// NoopGuard accepts everything (pre-Round-10D de-facto behavior).
	guard SuspiciousTranslationGuard
	group singleflight.Group
	// batchInFlight is the batch path's single-flight: cache key → the
	// in-flight batch entry that will resolve it. TranslateBatch claims the
	// keys it will send to the provider; an overlapping batch waits on the
	// claimed keys instead of re-sending them. The per-ref singleflight
	// group above never covered this path — the comment said it did.
	batchInFlight sync.Map // map[string]*batchInFlightEntry

	// freshTTL is how long cached values are considered fresh.
	// Lookups within this window are served straight from cache.
	freshTTL time.Duration
	// staleTTL is the additional window during which stale cached
	// values are served immediately while a background refresh runs
	// (stale-while-revalidate). Total cache lifetime is freshTTL +
	// staleTTL.
	staleTTL time.Duration
	// guardRejectionTTL bounds repeated provider calls for an output the
	// deterministic quality guard has just rejected.
	guardRejectionTTL time.Duration

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
	// GuardRejectionTTL defaults to 15 minutes. The cache stores only an
	// internal sentinel, never the rejected provider output.
	GuardRejectionTTL time.Duration
}

const guardRejectionSentinel = "\x00kielo:guard_rejected"

// NewSeam constructs a Seam. Pass Noop* implementations for any
// dependency that isn't wired yet — the seam still functions, just
// without caching / overrides / telemetry coverage.
//
// Round 10D back-compat: this constructor defaults persister to
// NoopPersister and guard to NoopGuard so existing callers continue
// to work without code change. Production wires persister + guard via
// NewSeamWith.
func NewSeam(registry *Registry, cache Cache, overrides OverrideStore, metrics Metrics, cfg SeamConfig) *Seam {
	return NewSeamWith(registry, cache, overrides, metrics, nil, nil, cfg)
}

// NewSeamWith constructs a Seam with the full Round 10D dependency set.
// Pass nil for any optional component (cache, overrides, metrics,
// persister, guard) to substitute the Noop* default.
//
// Production wiring (kielo-mobile-bff, kielo-user-service,
// kielo-content-service, kielo-communications-service, kielo-convo):
//
//	seam := localization.NewSeamWith(
//	    registry,
//	    cacheredis.New(redisClient),
//	    overridepgx.New(pgxPool),
//	    metrics.NewPrometheus(),
//	    localization.NewDynClientPersister(dynclient, "seam_autotranslate"),
//	    localization.NewCanonicalGuard(),
//	    localization.SeamConfig{},
//	)
func NewSeamWith(
	registry *Registry,
	cache Cache,
	overrides OverrideStore,
	metrics Metrics,
	persister TranslationPersister,
	guard SuspiciousTranslationGuard,
	cfg SeamConfig,
) *Seam {
	if cfg.FreshTTL <= 0 {
		cfg.FreshTTL = 24 * time.Hour
	}
	if cfg.StaleTTL <= 0 {
		cfg.StaleTTL = 6 * 24 * time.Hour
	}
	if cfg.GuardRejectionTTL <= 0 {
		cfg.GuardRejectionTTL = 15 * time.Minute
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
	if persister == nil {
		persister = NoopPersister{}
	}
	if guard == nil {
		guard = NoopGuard{}
	}
	return &Seam{
		registry:          registry,
		cache:             cache,
		overrides:         overrides,
		metrics:           metrics,
		persister:         persister,
		guard:             guard,
		freshTTL:          cfg.FreshTTL,
		staleTTL:          cfg.StaleTTL,
		guardRejectionTTL: cfg.GuardRejectionTTL,
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
// cache_swr, cache_miss_share, provider_call, provider_error,
// empty_translation (provider answered with an empty string), or
// guard_rejected (suspicious-translation guard refused the output).
// The last two fall back to English source text — a non-zero rate on
// either means users are silently seeing English.
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
		if s.resolveBatchCacheHit(ctx, r, target, entry, out) {
			continue
		}
		remaining2 = append(remaining2, r)
	}
	if len(remaining2) == 0 {
		return out
	}

	// Phase 3: provider batch call for cache misses, single-flighted per
	// key. Keys another batch is already translating are NOT re-sent; we
	// wait for that batch's answer instead. Before this the batch path had
	// no dedup at all (the singleflight.Group only wraps Translate), so the
	// app's 4s/12s/30s pending-refetches each re-sent the same cold page to
	// the bridge while the first call was still running.
	owned, shared := s.claimBatchKeys(remaining2)
	if len(owned) > 0 {
		RecordBudget(ctx, BudgetKindProviderCall, 1)
		s.providerBatchCall(ctx, owned, target, out)
		s.releaseBatchKeys(owned, out)
	}
	s.awaitSharedBatchKeys(ctx, shared, target, out)
	return out
}

// sharedResidue is a residue entry whose key another batch owns, together
// with THAT batch's in-flight entry. The pointer is captured at claim time and
// awaited directly: the owner deletes the map slot before it publishes, so a
// waiter that re-looked the key up could miss the result (and, with NoopCache
// or a failed cache write, fall back to source text after a successful
// translation) or observe an unrelated later request's entry.
type sharedResidue struct {
	residueEntry
	entry *batchInFlightEntry
}

// batchInFlightEntry is one claimed cache key: closed `done` + `value` once
// the owning batch has written its result for that key.
type batchInFlightEntry struct {
	done  chan struct{}
	value string
}

// claimBatchKeys splits the residue into keys this call owns (first claimant)
// and keys another in-flight batch already owns.
func (s *Seam) claimBatchKeys(remaining []residueEntry) (owned []residueEntry, shared []sharedResidue) {
	for _, r := range remaining {
		entry := &batchInFlightEntry{done: make(chan struct{})}
		if existing, loaded := s.batchInFlight.LoadOrStore(r.key, entry); loaded {
			shared = append(shared, sharedResidue{residueEntry: r, entry: existing.(*batchInFlightEntry)})
			continue
		}
		owned = append(owned, r)
	}
	return owned, shared
}

// releaseBatchKeys publishes the owner's results and frees the keys. Runs
// even when the provider failed — out[] then holds the source passthrough,
// which is exactly what a waiter should get too.
func (s *Seam) releaseBatchKeys(owned []residueEntry, out []string) {
	for _, r := range owned {
		raw, ok := s.batchInFlight.LoadAndDelete(r.key)
		if !ok {
			continue
		}
		// Publish BEFORE anyone could observe the slot as free: waiters hold
		// this pointer, so the write-then-close order is what they rely on.
		entry := raw.(*batchInFlightEntry)
		entry.value = out[r.idx]
		close(entry.done)
	}
}

// awaitSharedBatchKeys fills out[] for keys owned by another batch, waiting
// on the exact entry captured at claim time. Bounded by ctx: a waiter never
// outlives its own request budget, and on timeout it falls back to the source
// text like any other provider failure. No cache read is involved — the
// handoff must not depend on the cache implementation or a cache write
// succeeding.
func (s *Seam) awaitSharedBatchKeys(ctx context.Context, shared []sharedResidue, target string, out []string) {
	for _, r := range shared {
		select {
		case <-r.entry.done:
			out[r.idx] = r.entry.value
			s.metrics.Record(ctx, r.ref.Namespace, target, "cache_miss_share")
		case <-ctx.Done():
			out[r.idx] = r.ref.SourceText
			s.metrics.Record(ctx, r.ref.Namespace, target, "provider_error")
		}
	}
}

// residueEntry is the in-flight bookkeeping shape used by
// TranslateBatch + the per-phase batch helpers. Keeps the (idx, ref,
// cacheKey) triple coherent through override → cache → provider phases.
type residueEntry struct {
	idx int
	ref SourceRef
	key string // cache key
}

func (s *Seam) resolveBatchCacheHit(
	ctx context.Context,
	r residueEntry,
	target string,
	entry CacheEntry,
	out []string,
) bool {
	if entry.Value == guardRejectionSentinel {
		out[r.idx] = r.ref.SourceText
		s.metrics.Record(ctx, r.ref.Namespace, target, "guard_rejection_cache_hit")
		return true
	}
	if entry.Age <= s.freshTTL {
		out[r.idx] = entry.Value
		s.metrics.Record(ctx, r.ref.Namespace, target, "cache_hit")
		return true
	}
	if entry.Age <= s.freshTTL+s.staleTTL {
		s.kickoffSWR(ctx, r.ref, target, r.key)
		out[r.idx] = entry.Value
		s.metrics.Record(ctx, r.ref.Namespace, target, "cache_swr")
		return true
	}
	return false
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

// batchUnitKey identifies one translation unit: everything the provider
// actually sees. Two remaining entries with an equal key would reach it as
// byte-identical input, so they can only come back with the same answer.
//
// namespace+sourceID are in the key even though they don't change the text:
// refTranslationContext puts them in the prompt as disambiguating hints,
// precisely so two occurrences of a short ambiguous string ("Home" as
// navigation vs. as a noun) CAN translate differently. Collapsing across
// them would silently discard that. cacheKey is in the key so a collapsed
// item never carries a sibling's CacheKey into the provider's own cache
// decorator.
//
// This makes Go's dedup narrower than the Python seam's
// (seam.py::_provider_batch_call), which collapses on (text, role) alone —
// correct there because that path sends no context, so the provider has no
// hint to distinguish by.
type batchUnitKey struct {
	text      string
	role      TranslationRole
	namespace string
	sourceID  string
	cacheKey  string
}

// dedupeBatchItems collapses `remaining` into the distinct provider items it
// contains, and returns a function that re-expands the provider's results
// back to one-per-entry order. Callers do produce duplicates: a base word
// cited by two exercises in one batch, a string reused across steps of one
// lesson. Every original entry still gets its own cache write, persist and
// metric — only the provider fan-out collapses.
func dedupeBatchItems(remaining []residueEntry) (
	items []TranslationItem,
	expand func([]TranslationResult) []TranslationResult,
) {
	itemIndexOfUnit := make(map[batchUnitKey]int, len(remaining))
	unitOf := make([]batchUnitKey, len(remaining))
	items = make([]TranslationItem, 0, len(remaining))
	for i, r := range remaining {
		role := r.ref.Role
		if role == "" {
			role = RolePlain
		}
		unit := batchUnitKey{
			text:      r.ref.SourceText,
			role:      role,
			namespace: r.ref.Namespace,
			sourceID:  r.ref.SourceID,
			cacheKey:  r.key,
		}
		unitOf[i] = unit
		if _, seen := itemIndexOfUnit[unit]; seen {
			continue
		}
		itemIndexOfUnit[unit] = len(items)
		items = append(items, TranslationItem{
			Text:     r.ref.SourceText,
			Role:     role,
			CacheKey: r.key,
			Context:  refTranslationContext(r.ref),
		})
	}

	expand = func(deduped []TranslationResult) []TranslationResult {
		results := make([]TranslationResult, len(unitOf))
		for i, unit := range unitOf {
			results[i] = deduped[itemIndexOfUnit[unit]]
		}
		return results
	}
	return items, expand
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
		if len(remaining) > 0 {
			logTranslationFallback("provider_error", remaining[0].ref.Namespace, "batch", target, len(remaining),
				fmt.Sprintf("registry_resolve: %v", err))
		}
		return
	}

	items, expand := dedupeBatchItems(remaining)

	providerResults, err := provider.TranslateBatch(ctx, items, TranslateOptions{
		SourceLocale: TierASupportLocale,
		TargetLocale: target,
	})
	// Length is checked against the DEDUPED item list. Comparing against
	// len(remaining) would reject every correct response to a batch that
	// contained a duplicate.
	if err != nil || len(providerResults) != len(items) {
		for _, r := range remaining {
			out[r.idx] = r.ref.SourceText
			s.metrics.Record(ctx, r.ref.Namespace, target, "provider_error")
		}
		if len(remaining) > 0 {
			logTranslationFallback("provider_error", remaining[0].ref.Namespace, "batch", target, len(remaining),
				providerFailureCause(err, fmt.Sprintf("result_count_mismatch: got %d want %d",
					len(providerResults), len(items))))
		}
		return
	}

	results := expand(providerResults)

	// Persist + assign. Build a write-set for BatchSet when available.
	// Round 10D: parallel persistList tracks (ref, value) pairs that
	// pass the guard so we can write through to dynamic_translations
	// AFTER cache write. Siblings unaffected when one item rejects.
	writeSet := make(map[string]string, len(remaining))
	rejectionSet := make(map[string]string)
	persistList := make([]persistItem, 0, len(remaining))
	for i, r := range remaining {
		value := strings.TrimSpace(results[i].Text)
		if value == "" {
			// Distinct tag from provider_error: the provider answered
			// but produced nothing. A non-zero empty_translation rate
			// means users silently see English — alertable on its own.
			out[r.idx] = r.ref.SourceText
			s.metrics.Record(ctx, r.ref.Namespace, target, "empty_translation")
			logTranslationFallback("empty_translation", r.ref.Namespace, r.ref.SourceID, target, 1, "")
			continue
		}
		// Round 10D: per-item guard. Reject suspicious output BEFORE
		// cache + persist so junk doesn't poison either store.
		// Siblings continue unaffected. Distinct guard_rejected tag so
		// dashboards separate rejection volume from provider failures
		// without log spelunking.
		if s.guard.IsSuspicious(r.ref.SourceText, value, target) {
			out[r.idx] = r.ref.SourceText
			s.metrics.Record(ctx, r.ref.Namespace, target, "guard_rejected")
			logTranslationFallback("guard_rejected", r.ref.Namespace, r.ref.SourceID, target, 1, "")
			rejectionSet[r.key] = guardRejectionSentinel
			continue
		}
		out[r.idx] = value
		writeSet[r.key] = value
		persistList = append(persistList, persistItem{ref: r.ref, value: value})
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
	s.cacheGuardRejections(ctx, rejectionSet)
	// Round 10D: dynamic_translations write-through, per-item. Persister
	// failures swallowed at impl layer (translation succeeded; losing
	// the row only re-runs LLM on next request).
	for _, p := range persistList {
		_ = s.persister.Persist(ctx, p.ref, target, p.value)
	}
}

// persistItem is the in-flight bookkeeping shape for Round 10D
// per-item batch persistence. Decouples the BatchSet cache write (keyed
// by cacheKey) from the dynamic_translations write (keyed by ref).
type persistItem struct {
	ref   SourceRef
	value string
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
		if entry.Value == guardRejectionSentinel {
			return "guard_rejection_cache_hit", ref.SourceText
		}
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
	safego.Go("localization_seam_swr", func() {
		defer s.swrInFlight.Delete(cacheKey)
		bgCtx, cancel := context.WithTimeout(DetachBudget(context.WithoutCancel(ctx)), 30*time.Second)
		defer cancel()
		s.callProvider(bgCtx, ref, target, cacheKey)
	})
}

// callProvider routes through the registry, applies the suspicious-
// translation guard, persists the result to cache + the dynamic
// translations table, and returns the translated value. On any provider
// error / empty result / guard rejection, returns SourceText so the UI
// never renders blank.
//
// Round 10D: applies guard before cache write + persistence; persists
// successful translations to localization.dynamic_translations via
// the TranslationPersister so the next request for the same (namespace,
// source_id, source_version, target) tuple sees the row without
// re-invoking the LLM.
func (s *Seam) callProvider(ctx context.Context, ref SourceRef, target, cacheKey string) string {
	provider, err := s.registry.Resolve(TierASupportLocale, target)
	if err != nil {
		s.metrics.Record(ctx, ref.Namespace, target, "provider_error")
		logTranslationFallback("provider_error", ref.Namespace, ref.SourceID, target, 1,
			fmt.Sprintf("registry_resolve: %v", err))
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
		Context:  refTranslationContext(ref),
	}}
	results, err := provider.TranslateBatch(ctx, items, TranslateOptions{
		SourceLocale: TierASupportLocale,
		TargetLocale: target,
	})
	if err != nil || len(results) == 0 {
		s.metrics.Record(ctx, ref.Namespace, target, "provider_error")
		logTranslationFallback("provider_error", ref.Namespace, ref.SourceID, target, 1,
			providerFailureCause(err, "empty_result_set: provider returned 0 results"))
		return ref.SourceText
	}
	value := strings.TrimSpace(results[0].Text)
	if value == "" {
		// Provider answered but produced nothing — users silently see
		// English. Distinct tag so the rate is alertable on its own.
		s.metrics.Record(ctx, ref.Namespace, target, "empty_translation")
		logTranslationFallback("empty_translation", ref.Namespace, ref.SourceID, target, 1, "")
		return ref.SourceText
	}
	// Round 10D: quality gate. Reject suspicious output BEFORE cache
	// write + persistence so junk doesn't poison either store.
	if s.guard.IsSuspicious(ref.SourceText, value, target) {
		s.metrics.Record(ctx, ref.Namespace, target, "guard_rejected")
		logTranslationFallback("guard_rejected", ref.Namespace, ref.SourceID, target, 1, "")
		s.cacheGuardRejections(ctx, map[string]string{cacheKey: guardRejectionSentinel})
		return ref.SourceText
	}
	_ = s.cache.Set(ctx, cacheKey, value, s.freshTTL+s.staleTTL)
	// Round 10D: dynamic_translations write-through. Persister failures
	// must NOT bubble — the translation was successful, losing the
	// persistence row only means the next request re-runs the LLM
	// (degraded but correct). NoopPersister no-ops; production
	// DynClientPersister logs + returns silently.
	_ = s.persister.Persist(ctx, ref, target, value)
	return value
}

func (s *Seam) cacheGuardRejections(ctx context.Context, entries map[string]string) {
	if len(entries) == 0 || s.guardRejectionTTL <= 0 {
		return
	}
	if batchCache, ok := s.cache.(BatchCache); ok {
		_ = batchCache.BatchSet(ctx, entries, s.guardRejectionTTL)
		return
	}
	for key, value := range entries {
		_ = s.cache.Set(ctx, key, value, s.guardRejectionTTL)
	}
}

func (s *Seam) cacheKey(ref SourceRef, target string) string {
	return fmt.Sprintf("kielo:i18n:%s:%s:%s:%s", ref.Namespace, ref.SourceID, ref.SourceVersion, target)
}

// providerFailureCause separates the two failures that the provider_error
// fallback used to conflate. Both batch and single-item paths guard with
// `err != nil || <shape is wrong>`, so a provider that returned the WRONG
// NUMBER of results with err == nil logged identically to a transport error —
// a contract violation and an outage looked the same in the logs.
//
// Extracted rather than inlined at both sites so providerBatchCall stays under
// the gocyclo ceiling, and so the two paths cannot drift apart.
func providerFailureCause(err error, contractViolation string) string {
	if err != nil {
		return fmt.Sprintf("provider_call: %v", err)
	}
	return contractViolation
}

// logTranslationFallback makes every silent-English path visible in
// service logs. The Prometheus counter (kielo_translation_total) said the
// same thing to nobody after the 2026-08-18 sidecar retirement — the
// sanctioned pattern is a log-based metric, and log-based metrics need a
// line to match. Grep/alert on "[translation-fallback]".
func logTranslationFallback(source, namespace, sourceID, target string, count int, cause string) {
	// cause is APPENDED, never inserted: log-based metrics and alerts parse the
	// leading fields, so re-ordering them would silently break every consumer.
	//
	// Bounded at 200 runes because the cause is a provider error and an LLM
	// provider can echo its prompt back in a message — an unbounded %v risks
	// spilling source content into logs.
	if cause == "" {
		log.Printf("[translation-fallback] source=%s namespace=%s source_id=%s target=%s count=%d",
			source, namespace, sourceID, target, count)
		return
	}
	if r := []rune(cause); len(r) > 200 {
		cause = string(r[:200]) + "...(truncated)"
	}
	log.Printf("[translation-fallback] source=%s namespace=%s source_id=%s target=%s count=%d cause=%q",
		source, namespace, sourceID, target, count, cause)
}

// TierASupportLocale is the canonical English code per ADR-007. Lives
// here rather than referencing kielo-shared/locale to avoid a circular
// dependency (locale imports nothing; localization imports nothing
// app-specific). Keep in sync with locale.TierASupportLocale.
const TierASupportLocale = "en"

// refTranslationContext builds the disambiguation hint handed to the
// translation provider for a ref.
//
// Short UI strings are ambiguous out of context and the provider used to see
// nothing but the bare word: asking for "Sun" returned the Finnish "Aurinko"
// and the Vietnamese "Mặt Trời" — the celestial body — which the seam then
// persisted as the weekday abbreviation. The key ("ui.day_abbr.Sun") already
// says what the string is for, and it is right here; it simply was never sent.
//
// Returns nil when there is nothing useful to say, so providers that ignore
// context (and the opus-mt NMT backend, which cannot take instructions) see
// exactly the payload they saw before.
func refTranslationContext(ref SourceRef) map[string]any {
	sourceID := strings.TrimSpace(ref.SourceID)
	namespace := strings.TrimSpace(ref.Namespace)
	if sourceID == "" && namespace == "" {
		return nil
	}
	ctx := make(map[string]any, 2)
	if sourceID != "" {
		ctx["key"] = sourceID
	}
	if namespace != "" {
		ctx["namespace"] = namespace
	}
	return ctx
}
