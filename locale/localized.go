package locale

import (
	"encoding/json"
	"strings"
)

// PickLocalizedString resolves a locale-keyed string map into the value
// most appropriate for the requested support language, applying the
// canonical SupportLocaleCandidates chain (requested → English fallback)
// and returning fallback when nothing matches.
//
// Use this helper anywhere a service reads an author-supplied
// localized_titles / localized_descriptions / localized_<field> map and
// needs to pick the right per-locale string for a response. Centralizing
// the lookup avoids the drift we accumulated across kielo-mobile-bff,
// kielo-convo, and kielo-user-service — three services each carried a
// near-identical helper with subtly different empty-string handling.
//
// Contract:
//   - Trims surrounding whitespace before considering a value "present"
//     (empty string and pure-whitespace entries are treated as missing).
//   - When requested is empty, no candidate matches and fallback is
//     returned immediately so callers don't need to nil-check first.
//   - fallback may itself be empty — the caller is responsible for
//     wrapping with firstNonEmpty(...) when multiple fallbacks apply.
func PickLocalizedString(values map[string]string, requested, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	for _, candidate := range SupportLocaleCandidates(requested) {
		if value := strings.TrimSpace(values[candidate]); value != "" {
			return value
		}
	}
	return fallback
}

// PickLocalizedStringJSON is the jsonb-scan variant of PickLocalizedString
// for repositories that pull localized maps out of Postgres as []byte and
// don't want to decode the whole jsonb document into a domain struct.
//
// Returns fallback when the bytes are empty, malformed, or contain no
// usable value for the requested locale chain. JSON decode errors are
// intentionally swallowed because the column is COALESCE'd to '{}'::jsonb
// at query time — any decode failure means data corruption upstream,
// which is not something the per-request response path should fail on.
// (Callers that need decode-fault visibility should validate at ingest,
// not at read.)
func PickLocalizedStringJSON(raw []byte, requested, fallback string) string {
	if len(raw) == 0 {
		return fallback
	}
	var decoded map[string]string
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return fallback
	}
	return PickLocalizedString(decoded, requested, fallback)
}
