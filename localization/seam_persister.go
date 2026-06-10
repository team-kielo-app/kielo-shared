package localization

import "context"

// TranslationPersister is the seam's write-through persistence
// abstraction. Round 10D (sibling of Round 10A Python).
//
// The seam invokes Persist after every successful provider call so the
// (ref, target, value) tuple lands in localization.dynamic_translations
// as status='machine'. The next request for the same (namespace,
// source_id, source_version, target_locale) sees the row via the
// OverrideStore path (when admin promotes to 'approved'/'override') or
// the cache (Redis MGET) — either way the LLM is NOT re-invoked.
//
// Pre-Round-10D the Go seam wrote only to Redis cache. Operator intent
// (Round 10) was "treat ui-strings as data" — admin curates non-English
// in DB; English in code stays canonical source-of-truth. The
// persistence wire was missing on the Go side; this protocol closes it.
//
// Persistence is added at the seam layer (not at a higher autotranslate-
// callback) because:
//
//  1. The seam is the single chokepoint every consumer goes through
//     (Translate + TranslateBatch + future autotranslate hooks all
//     flow through callProvider / providerBatchCall). Higher placement
//     would skip the dynamicregistry miss-hook path Round 10D adds.
//  2. The seam's SourceRef.SourceVersion + Namespace already match
//     the persistence row shape — higher placements would have to
//     re-derive both from the (resource_id, english, _) tuple they
//     receive.
//  3. Errors are seam-layer concerns (cache failure already no-ops);
//     same shape lets persistence failures degrade gracefully without
//     bubbling to the user-facing request.
//
// Implementations MUST swallow internal errors. The seam falls back to
// SourceText on provider error; it must NOT additionally fall back when
// persistence fails (the translation was successful; losing the
// persistence row only means the next request re-runs the LLM, which is
// degraded but still correct).
//
// Production wires DynClientPersister (HTTP to kielo-localization) at
// every dynamicregistry call site. Tests use MapPersister for
// assertions. Default NoopPersister preserves pre-Round-10D behavior
// for tests + envs that haven't wired the new contract yet.
type TranslationPersister interface {
	Persist(ctx context.Context, ref SourceRef, targetLocale, translatedText string) error
}

// NoopPersister is a TranslationPersister that swallows every call. Use
// in tests + envs where kielo-localization is unreachable. Pre-Round-10D
// services that haven't wired a real persister default to this — same
// backward-compat contract as NoopCache / NoopOverrideStore.
type NoopPersister struct{}

// Persist implements TranslationPersister.
func (NoopPersister) Persist(_ context.Context, _ SourceRef, _, _ string) error {
	return nil
}

// MapPersister is a deterministic in-memory persister for unit tests.
// Tests assert on Calls to verify the seam invoked persistence with the
// expected (ref, target, value) tuple.
//
// The tuple shape mirrors the persistence row that would land in
// localization.dynamic_translations: (namespace, source_id,
// source_version, target_locale, translated_text). source_text / role
// are dropped because the row doesn't carry them — the source_version
// hash IS the de-facto reference to source_text.
type MapPersister struct {
	Calls []PersistCall
}

// PersistCall records a single Persist invocation for test assertions.
// Mirrors the Python MapPersister.calls tuple shape.
type PersistCall struct {
	Namespace      string
	SourceID       string
	SourceVersion  string
	TargetLocale   string
	TranslatedText string
}

// Persist implements TranslationPersister. NOT goroutine-safe; tests
// that exercise concurrent paths should wrap with a mutex.
func (p *MapPersister) Persist(_ context.Context, ref SourceRef, targetLocale, translatedText string) error {
	p.Calls = append(p.Calls, PersistCall{
		Namespace:      ref.Namespace,
		SourceID:       ref.SourceID,
		SourceVersion:  ref.SourceVersion,
		TargetLocale:   targetLocale,
		TranslatedText: translatedText,
	})
	return nil
}
