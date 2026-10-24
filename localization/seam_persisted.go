package localization

import (
	"context"
	"regexp"
	"strings"
)

// PersistedStore reads back the status='machine' rows the seam's
// TranslationPersister wrote to localization.dynamic_translations. Same
// shape as OverrideStore, different status filter: a row matches only when
// its source_version equals the requested one.
//
// The seam consults it after an override miss and a cache miss, before the
// provider, so a translation that already exists is never re-bought from the
// LLM when its cache entry expires. The seam applies the stand-in rule itself
// (see usablePersisted). Stores that also implement BatchLookup
// (BatchOverrideStore's method set) collapse a batch to one query.
//
// Optional: a Seam without one behaves exactly as before. Attach with
// Seam.WithPersisted.
type PersistedStore interface {
	Lookup(ctx context.Context, namespace, sourceID, sourceVersion, targetLocale string) (value string, found bool)
}

// NoopPersistedStore always misses.
type NoopPersistedStore struct{}

func (NoopPersistedStore) Lookup(context.Context, string, string, string, string) (string, bool) {
	return "", false
}

// WithPersisted attaches the persisted-translation read tier and returns the
// seam. Call it while wiring, before the seam serves traffic.
func (s *Seam) WithPersisted(store PersistedStore) *Seam {
	s.persisted = store
	return s
}

var (
	placeholderRE = regexp.MustCompile(`\{\{[^}]*\}\}|%[sdvqtf]|%%`)
	wordRE        = regexp.MustCompile(`\p{L}{3,}`)
)

const proseMinWords = 5

func normalizedText(v string) string {
	return strings.ToLower(strings.Join(strings.Fields(v), " "))
}

// IsSourceEcho reports whether translated equals source, ignoring
// whitespace and case. Mirrors Python is_source_echo.
func IsSourceEcho(source, translated string) bool {
	n := normalizedText(source)
	return n != "" && normalizedText(translated) == n
}

// IsProse reports whether text is long enough (five words of three or more
// letters, placeholders excluded) that an identical translation is
// implausible. Mirrors Python is_prose.
func IsProse(text string) bool {
	return len(wordRE.FindAllString(placeholderRE.ReplaceAllString(text, " "), -1)) >= proseMinWords
}

// usablePersisted reports whether a persisted machine row may be served. A
// row identical to a prose source is a stand-in persisted before provenance
// tracking, not a translation, and counts as a miss.
func usablePersisted(ref SourceRef, value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	return !IsSourceEcho(ref.SourceText, value) || !IsProse(ref.SourceText)
}

func (s *Seam) persistedRow(ctx context.Context, ref SourceRef, target string) (string, bool) {
	if s.persisted == nil {
		return "", false
	}
	return s.persisted.Lookup(ctx, ref.Namespace, ref.SourceID, ref.SourceVersion, target)
}

// resolvePersistedBatch serves the residue entries that have a usable
// persisted row, refills the cache for them, and returns the rest. Entries
// whose row exists but is unusable keep it in .known so an identical
// provider answer is not persisted again.
func (s *Seam) resolvePersistedBatch(ctx context.Context, remaining []residueEntry, target string, out []string) []residueEntry {
	if s.persisted == nil || len(remaining) == 0 {
		return remaining
	}
	rows := s.batchPersistedLookup(ctx, remaining, target)
	still := make([]residueEntry, 0, len(remaining))
	served := make(map[string]string)
	for _, r := range remaining {
		row, ok := rows[OverrideBatchKey(r.ref.Namespace, r.ref.SourceID, r.ref.SourceVersion)]
		if !ok {
			still = append(still, r)
			continue
		}
		if usablePersisted(r.ref, row) {
			out[r.idx] = row
			served[r.key] = row
			s.metrics.Record(ctx, r.ref.Namespace, target, "persisted")
			continue
		}
		r.known = row
		still = append(still, r)
	}
	s.cacheWrite(ctx, served)
	return still
}

func (s *Seam) batchPersistedLookup(ctx context.Context, residue []residueEntry, target string) map[string]string {
	if batchStore, ok := s.persisted.(BatchOverrideStore); ok {
		refs := make([]OverrideRef, len(residue))
		for i, r := range residue {
			refs[i] = OverrideRef{Namespace: r.ref.Namespace, SourceID: r.ref.SourceID, SourceVersion: r.ref.SourceVersion}
		}
		if hits, err := batchStore.BatchLookup(ctx, refs, target); err == nil {
			return hits
		}
	}
	hits := make(map[string]string, len(residue))
	for _, r := range residue {
		if val, ok := s.persisted.Lookup(ctx, r.ref.Namespace, r.ref.SourceID, r.ref.SourceVersion, target); ok {
			hits[OverrideBatchKey(r.ref.Namespace, r.ref.SourceID, r.ref.SourceVersion)] = val
		}
	}
	return hits
}

func (s *Seam) cacheWrite(ctx context.Context, entries map[string]string) {
	if len(entries) == 0 {
		return
	}
	ttl := s.freshTTL + s.staleTTL
	if batchCache, ok := s.cache.(BatchCache); ok {
		_ = batchCache.BatchSet(ctx, entries, ttl)
		return
	}
	for k, v := range entries {
		_ = s.cache.Set(ctx, k, v, ttl)
	}
}
