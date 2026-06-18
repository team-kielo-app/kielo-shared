package vietnamese

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/team-kielo-app/kielo-shared/locale/supportregistry"
)

// Tests for the hardcoded Vietnamese override tables used by the
// ingest + learn engines as a zero-latency short-circuit around the
// translation API. These overrides are hand-verified and high-traffic;
// if one silently falls through to the general translator (via a typo
// in the map or in the caller's input normalization), the learner's
// reading view gets a lower-quality gloss or, worse, nothing at all
// when the translator rate-limits.
//
// 2026-05-17 cleanup: the legacy `DictionaryGlossOverride` /
// `GrammarConceptFallback` / `DictionaryTermOverride` shims were
// deleted (zero non-test callers remained). The per-locale variants
// `GlossOverrideFor(value, locale)` / `GrammarConceptOverrideFor` /
// `TermOverrideFor` are the canonical API and are tested below.
//
// The contract each function exports:
//   - GlossOverrideFor: case-insensitive, trims whitespace,
//     returns "" on miss. Per-locale (vi seeded; other locales
//     fall back to the English seed).
//   - TermOverrideFor: same contract, different table.
//   - KnownLemmaOverride: case-insensitive, trims whitespace,
//     canonicalizes pronoun lemmas that morphology APIs may not
//     handle correctly. Locale-agnostic — the lemma IS the canonical
//     value.
//   - GrammarConceptOverrideFor: case-SENSITIVE, trims whitespace only.
//     This divergence is intentional: grammar concept names are
//     canonical tokens (e.g. "Genetiivi (-n)"), not free text.

func TestKnownLemmaOverride_CanonicalizesPronounLemmas(t *testing.T) {
	// Morphology APIs sometimes return "minä" as its own lemma and
	// sometimes decline it further. KnownLemmaOverride short-circuits
	// to the identity so the canonical pronoun wins.
	assert.Equal(t, "minä", KnownLemmaOverride("minä"))
	assert.Equal(t, "hän", KnownLemmaOverride("hän"))
	assert.Equal(t, "he", KnownLemmaOverride("he"))
}

func TestKnownLemmaOverride_CaseInsensitive(t *testing.T) {
	assert.Equal(t, "minä", KnownLemmaOverride("MINÄ"))
	assert.Equal(t, "sinä", KnownLemmaOverride(" Sinä "))
}

func TestKnownLemmaOverride_MissingReturnsEmpty(t *testing.T) {
	// Non-pronoun term must fall through so the real morphology
	// path runs. Returning a spurious lemma here would corrupt
	// downstream base-word resolution.
	assert.Equal(t, "", KnownLemmaOverride("talo"))
	assert.Equal(t, "", KnownLemmaOverride(""))
}

// ----------------------------------------------------------------------------
// ADR-008 supportregistry variants: GlossOverrideFor / GrammarConceptOverrideFor / TermOverrideFor
// ----------------------------------------------------------------------------
//
// These tests pin the per-locale resolution contract. The legacy
// VI-hardcoded wrappers were removed 2026-05-17; the *OverrideFor
// variants are the canonical API.

func TestGlossOverrideFor_ResolvesViWhenLocaleIsVi(t *testing.T) {
	// Post-Round-10C: bare seed has English-only entries. Vi values
	// come from localization.dynamic_translations via the dynamicregistry
	// wrap (admin curation + Round 10D autotranslate fill); the bare-
	// seed path returns English as fallback.
	assert.Equal(t, "I", GlossOverrideFor("I", "vi"))
	assert.Equal(t, "shop, store", GlossOverrideFor("shop, store", "vi"))
	assert.Equal(t, "train", GlossOverrideFor("TRAIN", "vi"))
}

func TestGlossOverrideFor_FallsBackToEnglishForOtherLocales(t *testing.T) {
	// A support locale we haven't seeded (sv) MUST fall through to
	// the English seed, NOT return "" and NOT return the VI override.
	// This is the ADR-008 fallback contract: missing locale → English
	// seed → never silently wrong.
	assert.Equal(t, "I", GlossOverrideFor("I", "sv"))
	assert.Equal(t, "shop, store", GlossOverrideFor("shop, store", "sv"))
	// Empty locale string MUST also fall through to English rather
	// than returning "" — defensive against callers that haven't
	// resolved a support locale yet.
	assert.Equal(t, "they", GlossOverrideFor("they", ""))
}

func TestGlossOverrideFor_MissReturnsEmpty(t *testing.T) {
	// "xyz" has no seed at all → return "" so the caller falls through
	// to the upstream translator path (as in the pre-registry impl).
	assert.Equal(t, "", GlossOverrideFor("xyz not a gloss", "vi"))
	assert.Equal(t, "", GlossOverrideFor("", "vi"))
	assert.Equal(t, "", GlossOverrideFor("  ", "vi"))
}

func TestGlossOverrideFor_CaseInsensitive(t *testing.T) {
	// Same case-insensitivity contract as the legacy DictionaryGlossOverride.
	// Post-Round-10C: bare seed returns English (vi via dynamicregistry).
	assert.Equal(t, "I", GlossOverrideFor("i", "vi"))
	assert.Equal(t, "they", GlossOverrideFor("They", "vi"))
}

func TestGrammarConceptOverrideFor_ResolvesViWhenLocaleIsVi(t *testing.T) {
	// Post-Round-10C: bare seed has English-only entries. Vi values
	// come from localization.dynamic_translations via the dynamicregistry
	// wrap; the bare-seed path returns the canonical (which IS the
	// English seed value, since the key === English for grammar concepts).
	assert.Equal(t, "Genetiivi (-n)", GrammarConceptOverrideFor("Genetiivi (-n)", "vi"))
	assert.Equal(t, "Preesens", GrammarConceptOverrideFor("Preesens", "vi"))
	assert.Equal(t, "Imperatiivi", GrammarConceptOverrideFor("Imperatiivi", "vi"))
}

func TestGrammarConceptOverrideFor_FallsBackToCanonicalForOtherLocales(t *testing.T) {
	// Non-VI support locales get the canonical name back (the English
	// seed equals the canonical input), so the UI still renders
	// something readable. NOT "" and NOT the VI translation.
	assert.Equal(t, "Genetiivi (-n)", GrammarConceptOverrideFor("Genetiivi (-n)", "sv"))
	assert.Equal(t, "Preesens", GrammarConceptOverrideFor("Preesens", "en"))
	assert.Equal(t, "Present Tense", GrammarConceptOverrideFor("Present Tense", ""))
}

func TestGrammarConceptOverrideFor_CaseSensitive(t *testing.T) {
	// Same case-sensitivity contract as GrammarConceptFallback —
	// lowercase variants are NOT in the registry and must return "".
	assert.Equal(t, "", GrammarConceptOverrideFor("preesens", "vi"))
	assert.Equal(t, "", GrammarConceptOverrideFor("PRESENT TENSE", "vi"))
}

func TestGrammarConceptOverrideFor_MissReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", GrammarConceptOverrideFor("", "vi"))
	assert.Equal(t, "", GrammarConceptOverrideFor("Not a real concept", "vi"))
}

func TestTermOverrideFor_ResolvesViWhenLocaleIsVi(t *testing.T) {
	// Post-Round-10C: bare seed has English-only gloss entries; vi
	// values come from localization.dynamic_translations via the
	// dynamicregistry wrap. The bare-seed path returns the English
	// canonical that termOverrides routes to.
	assert.Equal(t, "I", TermOverrideFor("minä", "vi"))
	assert.Equal(t, "you", TermOverrideFor("sinä", "vi"))
	assert.Equal(t, "he/she", TermOverrideFor("hän", "vi"))
	assert.Equal(t, "it", TermOverrideFor("se", "vi"))
	assert.Equal(t, "we", TermOverrideFor("me", "vi"))
	// "te" is the plural "you" — the registry has a separate
	// "you (plural)" key.
	assert.Equal(t, "you (plural)", TermOverrideFor("te", "vi"))
	assert.Equal(t, "they", TermOverrideFor("he", "vi"))
}

func TestTermOverrideFor_FallsBackToEnglishForOtherLocales(t *testing.T) {
	// Non-VI support locales get the canonical English form back —
	// "minä" → "I", "te" → "you (plural)", etc. This is the ADR-008
	// English fallback contract and is what makes TermOverrideFor
	// callable from a non-VI dictionary handler.
	assert.Equal(t, "I", TermOverrideFor("minä", "en"))
	assert.Equal(t, "you", TermOverrideFor("sinä", "sv"))
	assert.Equal(t, "you (plural)", TermOverrideFor("te", "en"))
	assert.Equal(t, "they", TermOverrideFor("he", ""))
}

func TestTermOverrideFor_MissReturnsEmpty(t *testing.T) {
	// Input that isn't a known Finnish pronoun → "" so the caller
	// falls through to the regular dictionary path.
	assert.Equal(t, "", TermOverrideFor("talo", "vi"))
	assert.Equal(t, "", TermOverrideFor("", "vi"))
	assert.Equal(t, "", TermOverrideFor("   ", "vi"))
}

func TestTermOverrideFor_CaseInsensitive(t *testing.T) {
	// Post-Round-10C: bare seed returns English canonical.
	assert.Equal(t, "I", TermOverrideFor("MINÄ", "vi"))
	assert.Equal(t, "he/she", TermOverrideFor(" Hän ", "vi"))
}

func TestTermOverrideFor_FiPronounsHaveCorrespondingGlossSeeds(t *testing.T) {
	// Post-Round-10C invariant: every FI key in finnishPronounToEnglish
	// MUST round-trip through the gloss registry with both en and
	// (post-Round-10C) the en-fallback path for vi — non-empty results
	// in both cases prove the canonical English glosses are seeded.
	// Vi values land in localization.dynamic_translations via the
	// dynamicregistry wrap at runtime; they are NOT in the bare seed.
	for fi, english := range finnishPronounToEnglish {
		// Vi-path: post-Round-10C this is the English fallback. Must
		// be non-empty so the dynamicregistry override probe has a
		// source_version to derive (per dynamicregistry.sourceVersionFor:
		// empty English → silently disable probe).
		viGot := GlossOverrideFor(english, "vi")
		if viGot == "" {
			t.Errorf("FI pronoun %q → English %q has no gloss seed (vi-path fallback empty)", fi, english)
		}
		// And the EN-direct path.
		enGot := GlossOverrideFor(english, "en")
		if enGot == "" {
			t.Errorf("FI pronoun %q → English %q has no gloss seed (en-direct path empty)", fi, english)
		}
	}
}

func TestTermOverrideFor_TableInvariant_EveryFiKeyResolvesToEnglish(t *testing.T) {
	// Post-Round-10C invariant: every entry in finnishPronounToEnglish
	// (the canonical English mapping) MUST resolve via
	// TermOverrideFor(fi, "vi") to the SAME English string (not the
	// retired vi-seed value). Vi values come from
	// localization.dynamic_translations via the dynamicregistry wrap;
	// the bare-seed path returns the English canonical.
	for fi, expectedEn := range finnishPronounToEnglish {
		got := TermOverrideFor(fi, "vi")
		assert.Equal(t, expectedEn, got,
			"FI pronoun %q: en-canonical=%q registry=%q (post-Round-10C bare seed returns en)",
			fi, expectedEn, got)
	}
}

// Round 6 C3 (2026-06-09): wrap dictionarySeed with
// dynamicregistry.Registry via SetDictionaryRegistry. These tests
// pin:
//
//   1. DictionarySeed() returns the canonical MapRegistry so
//      consumers can wrap it.
//   2. The default (pre-Set) state resolves via the seed.
//   3. SetDictionaryRegistry swaps the registry; subsequent
//      Resolve calls go through the new registry.
//   4. SetDictionaryRegistry(nil) is a no-op (preserves current).
//   5. The English-seed invariant — every gloss + grammar key has
//      an English row, so the dynamicregistry override probe will
//      fire (and not silently short-circuit per the inert-wrap
//      defect class documented in Round 5).

func TestDictionarySeed_ReturnsRegistry(t *testing.T) {
	seed := DictionarySeed()
	if seed == nil {
		t.Fatal("DictionarySeed() returned nil")
	}
}

func TestDictionaryRegistry_DefaultResolvesViaSeed(t *testing.T) {
	// Post-Round-10C: bare seed has English-only entries. Vi values
	// come from localization.dynamic_translations via the dynamicregistry
	// wrap; the bare-seed path returns the English canonical.
	got := GlossOverrideFor("train", "vi")
	assert.Equal(t, "train", got)
	got = GrammarConceptOverrideFor("Genitive", "vi")
	assert.Equal(t, "Genitive", got)
}

func TestSetDictionaryRegistry_SwapsRegistry(t *testing.T) {
	restoreDictionarySeed(t)

	// Swap in a sentinel registry that returns a known marker for
	// any (key, locale). The helpers funnel through the registry,
	// so GlossOverrideFor should now return the sentinel.
	sentinel := &sentinelRegistry{marker: "SENTINEL_XYZ"}
	SetDictionaryRegistry(sentinel)

	got := GlossOverrideFor("train", "vi")
	assert.Equal(t, "SENTINEL_XYZ", got,
		"after SetDictionaryRegistry, helpers must go through new registry")
}

func TestSetDictionaryRegistry_NilIsNoOp(t *testing.T) {
	restoreDictionarySeed(t)

	// Sanity: starting state is the seed. Post-Round-10C bare seed
	// returns the English canonical.
	assert.Equal(t, "train", GlossOverrideFor("train", "vi"))

	// nil swap MUST NOT clobber the existing registry.
	SetDictionaryRegistry(nil)

	assert.Equal(t, "train", GlossOverrideFor("train", "vi"),
		"SetDictionaryRegistry(nil) must preserve current registry")
}

func TestDictionarySeed_EnglishIsSeededForAllKeys(t *testing.T) {
	// Round 5 / Round 6 invariant — every key in the seed MUST have
	// an English row. The dynamicregistry override probe uses the
	// English seed text to derive source_version; missing English
	// silently disables the probe (per
	// kielo-shared/locale/supportregistry/dynamicregistry/
	// registry.go:sourceVersionFor).
	//
	// Cover both gloss + grammar namespaces by walking the same
	// hand-curated tables the seed init walks.

	// Glosses — empirical pin against a sample of canonical keys
	// from the seed init (lines 84-95 in vietnamese.go).
	for _, en := range []string{
		"I", "me", "you", "you (plural)", "for you / to you",
		"he/she", "he / she", "it", "we", "they",
		"to be", "shop, store", "train",
	} {
		key := glossKey(en)
		// Resolve against EN should NOT return the key string —
		// that would mean the English row is missing.
		got := dictionarySeed.Resolve(t.Context(), key, "en")
		if got == string(key) {
			t.Errorf("English seed missing for gloss key %q (would "+
				"silently disable dynamicregistry override probe)", en)
		}
	}

	// Grammar concepts — same pin.
	for _, canonical := range []string{
		"Genetiivi (-n)", "Genitive Case", "Genitive",
		"Partitiivi", "Partitive Case",
		"Imperatiivi", "Imperative Mood",
		"Preesens", "Present Tense",
		"Perfekti", "Perfect Tense",
		"Imperfekti", "Past Tense",
	} {
		key := grammarKey(canonical)
		got := dictionarySeed.Resolve(t.Context(), key, "en")
		if got == string(key) {
			t.Errorf("English seed missing for grammar key %q "+
				"(would silently disable dynamicregistry override "+
				"probe)", canonical)
		}
	}
}

// restoreDictionarySeed restores the package registry to its seed
// state at test cleanup so tests are order-independent.
func restoreDictionarySeed(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		dictionaryRegistryMu.Lock()
		dictionaryRegistry = dictionarySeed
		dictionaryRegistryMu.Unlock()
	})
}

// sentinelRegistry is a test-only registry that always returns
// `marker` regardless of (key, locale). Used to prove
// SetDictionaryRegistry actually swaps the registry.
type sentinelRegistry struct {
	marker string
}

func (s *sentinelRegistry) Resolve(_ context.Context, _ supportregistry.Key, _ string) string {
	return s.marker
}

func (s *sentinelRegistry) ResolveTemplate(_ context.Context, _ supportregistry.Key, _ string, _ map[string]any) string {
	return s.marker
}

func (s *sentinelRegistry) SupportedLocales() []string {
	return []string{"en", "vi"}
}

func (s *sentinelRegistry) CoverageReport() map[string]supportregistry.CoverageStats {
	return map[string]supportregistry.CoverageStats{}
}
