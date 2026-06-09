package dynamicregistry

import (
	"context"
	"sync"
)

// Translator is the dynamicregistry's autotranslate-on-miss hook
// (Round 10D). When Resolve hits the DB-miss path AND a Translator is
// wired, the Registry spawns a background goroutine that translates
// the seed English value into target locale + persists to
// localization.dynamic_translations. The CURRENT request still returns
// the seed English (non-blocking). The NEXT request for the same
// (key, locale) sees the row via DB probe and returns the translated
// value.
//
// Production wiring: see the SeamTranslator adapter at
// seam_translator.go which lifts a localization.Seam (with persister +
// guard wired) into a Translator. Tests can use NoopTranslator (Round
// 10D default) or a recording stub.
//
// Implementations MUST be goroutine-safe — Translate runs in a
// fire-and-forget goroutine spawned from Resolve, which can be called
// concurrently from any number of request handlers.
//
// Implementations MUST swallow internal errors. The dynamicregistry
// has already returned to the user with seed English; logging is the
// only operator surface for translate failures (Translator
// implementations log internally; the dynamicregistry doesn't see the
// error).
//
// The Translate signature carries everything the implementation needs
// to invoke the seam + dynclient: resource_type (the namespace),
// resource_id (the key string), source_version (the SHA256-prefix the
// dynamicregistry computed from the seed English text), sourceText
// (the English to translate), and targetLocale.
type Translator interface {
	Translate(ctx context.Context, resourceType, resourceID, sourceVersion, sourceText, targetLocale string)
}

// NoopTranslator is the dynamicregistry's default Translator. Use in
// tests + envs where the autotranslate-on-miss path is not wired.
// Pre-Round-10D this is the de-facto behaviour — the Registry just
// returned seed English on DB-miss without queuing any LLM fill.
//
// Backward-compat default. Wired automatically when WithTranslator is
// not called on the Registry constructor.
type NoopTranslator struct{}

// Translate implements Translator. Drops the call silently.
func (NoopTranslator) Translate(_ context.Context, _, _, _, _, _ string) {}

// WithTranslator wires the Round 10D autotranslate-on-miss hook onto
// the Registry. The Translator runs from a background goroutine; the
// dynamicregistry does NOT block on it. Concurrent misses for the same
// (key, locale) tuple are deduplicated via the in-flight map so only
// ONE LLM call fires per tuple per process.
//
// Pass nil to keep the default NoopTranslator (autotranslate disabled).
//
// Production wiring example (kielo-mobile-bff main.go):
//
//	seam := localization.NewSeamWith(
//	    registry,
//	    cacheredis.New(redisClient),
//	    overridepgx.New(pgxPool),
//	    metrics.NewPrometheus(),
//	    seampersister.NewDynClient(dynClient, "seam_autotranslate_bff", logger),
//	    localization.NewCanonicalGuard(),
//	    localization.SeamConfig{},
//	)
//	translator := dynamicregistry.NewSeamTranslator(seam)
//	dyn := dynamicregistry.New(seed, pgxPool, cache,
//	    dynamicregistry.WithTranslator(translator))
func WithTranslator(t Translator) Option {
	return func(r *Registry) {
		if t != nil {
			r.translator = t
		}
	}
}

// queueAutotranslate fires a background goroutine that invokes the
// Registry's Translator for (key, sourceVersion, sourceText, locale).
// Concurrent calls for the same (key, locale) tuple are deduplicated
// via the inflight map so only ONE LLM call fires per tuple per
// process per request-cycle.
//
// The inflight map entry is cleared when the goroutine returns,
// allowing the next miss for the same tuple to re-queue (e.g. if the
// first attempt failed and didn't persist).
//
// Round 10D dedupe shape:
//
//   - One process-local sync.Map keyed by "<key>|<locale>" (the
//     (key, locale) tuple).
//   - LoadOrStore returns ok=true when the entry already exists,
//     letting subsequent goroutines short-circuit without spawning.
//
// This mirrors the Seam.kickoffSWR pattern at
// kielo-shared/localization/seam.go (Sweep TTTT-B background refresh
// dedupe). Same primitive applied at the Registry-miss boundary.
//
// Background goroutines use context.WithoutCancel of the request ctx
// so request-cancellation (mobile disconnect) doesn't kill the LLM
// call in flight. The Translator implementation is expected to apply
// its own bounded timeout (the SeamTranslator wraps the Seam, which
// has its own 30s timeout per kickoffSWR).
func (r *Registry) queueAutotranslate(ctx context.Context, key, sourceVersion, sourceText, locale string) {
	if r == nil || r.translator == nil {
		return
	}
	if _, ok := r.translator.(NoopTranslator); ok {
		return
	}
	if sourceText == "" || locale == "" {
		return
	}
	dedupeKey := key + "|" + locale
	if _, loaded := r.autotranslateInflight.LoadOrStore(dedupeKey, struct{}{}); loaded {
		return
	}
	bgCtx := context.WithoutCancel(ctx)
	go func() {
		defer r.autotranslateInflight.Delete(dedupeKey)
		r.translator.Translate(bgCtx, r.resType, key, sourceVersion, sourceText, locale)
	}()
}

// autotranslateInflight is a process-local sync.Map (string ->
// struct{}) used to deduplicate concurrent autotranslate goroutines
// for the same (key, locale) tuple. Documented as a Registry field
// rather than a separate struct so all Round 10D state lives next to
// the existing Registry concerns.
//
// Keys: "<resource_id>|<locale>" (no resource_type prefix since the
// Registry is scoped to a single resource type via WithResourceType).
//
// Mirror of Seam.swrInFlight in kielo-shared/localization/seam.go.
type _ = sync.Map // doc-only anchor; the actual field is on Registry
