package localization

import "context"

// OverrideStore looks up admin-approved translations from the
// localization.translations table. The seam consults overrides BEFORE
// the cache so admin-curated strings always win over machine-generated
// ones — even fresh cache entries get bypassed.
//
// Concrete implementations live service-side because they need a
// database handle; this shared library only defines the contract +
// noop variant.
//
// Status + version semantics expected by the seam:
//
//   - 'approved' rows MATCHING the requested sourceVersion are returned
//     as a hit. An admin signed off on this translation for THIS source
//     text; serve it.
//   - 'override' rows (admin-edited after a machine translation) MATCHING
//     sourceVersion are returned as a hit.
//   - Rows where stored source_version != requested sourceVersion are
//     NOT returned (the canonical English source has been edited under
//     the admin; their translation is now reviewed against stale text).
//     Implementations should also flip stale rows' status to
//     'pending_review' so admin-ui surfaces them for re-review.
//   - 'pending_review' / 'draft' rows are NOT returned — admin hasn't
//     signed off.
//
// The implementation MUST filter on status + source_version server-side
// so each Lookup is one indexed query.
type OverrideStore interface {
	// Lookup returns the override value when an approved or override
	// row exists AND its stored source_version matches the requested
	// sourceVersion. found=false means no usable override; the seam
	// falls through to the cache + provider chain. Implementations
	// that encounter a row with mismatched source_version should mark
	// it pending_review out-of-band (not on the read path) and return
	// found=false so the request still serves a fresh translation.
	Lookup(ctx context.Context, namespace, sourceID, sourceVersion, targetLocale string) (value string, found bool)
}

// BatchOverrideStore is the optional batch-aware extension. Impls
// implementing this interface receive a list of refs and return a map
// from `(namespace|sourceID|sourceVersion)` → value for every override
// that matched the (status + source_version) gate. Sweep TTTT-B
// closes the N+1 DB-query pattern that pre-TTTT made list endpoints
// issue 1 pgx QueryRow per row.
//
// Wire-shape:
//   - keys formatted via OverrideBatchKey for deterministic packing
//   - misses are omitted (callers check map-presence, not value-non-empty)
//   - one SQL round-trip per call (composite-tuple `(namespace,
//     source_id, source_version) IN (...)` clause)
type BatchOverrideStore interface {
	OverrideStore
	BatchLookup(
		ctx context.Context,
		refs []OverrideRef,
		targetLocale string,
	) (map[string]string, error)
}

// OverrideRef is the input shape for BatchLookup. Pack the same
// three identity fields the per-row Lookup signature carries.
type OverrideRef struct {
	Namespace     string
	SourceID      string
	SourceVersion string
}

// OverrideBatchKey is the canonical packed key for BatchLookup results.
// Same shape as MapOverrideStore's key but exposed publicly so callers
// can build lookup keys without depending on the package-private
// MapOverrideStore implementation.
func OverrideBatchKey(namespace, sourceID, sourceVersion string) string {
	return namespace + "|" + sourceID + "|" + sourceVersion
}

// NoopOverrideStore is an OverrideStore that always returns "not
// found". Use in environments without a localization DB or in unit
// tests of the seam where overrides aren't under test.
type NoopOverrideStore struct{}

func (NoopOverrideStore) Lookup(context.Context, string, string, string, string) (string, bool) {
	return "", false
}

// MapOverrideStore is a deterministic in-memory OverrideStore for
// unit tests. Keys are formatted "namespace|sourceID|sourceVersion|targetLocale";
// callers that don't care about version semantics in tests can use
// the literal "*" for sourceVersion as a wildcard match.
type MapOverrideStore map[string]string

func (m MapOverrideStore) Lookup(_ context.Context, namespace, sourceID, sourceVersion, targetLocale string) (string, bool) {
	if value, ok := m[namespace+"|"+sourceID+"|"+sourceVersion+"|"+targetLocale]; ok {
		return value, true
	}
	if value, ok := m[namespace+"|"+sourceID+"|*|"+targetLocale]; ok {
		return value, true
	}
	return "", false
}
