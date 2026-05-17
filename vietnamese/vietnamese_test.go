package vietnamese

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
	assert.Equal(t, "tôi", GlossOverrideFor("I", "vi"))
	assert.Equal(t, "cửa hàng, tiệm", GlossOverrideFor("shop, store", "vi"))
	assert.Equal(t, "tàu hỏa", GlossOverrideFor("TRAIN", "vi"))
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
	assert.Equal(t, "tôi", GlossOverrideFor("i", "vi"))
	assert.Equal(t, "họ", GlossOverrideFor("They", "vi"))
}

func TestGrammarConceptOverrideFor_ResolvesViWhenLocaleIsVi(t *testing.T) {
	assert.Equal(t, "cách sở hữu", GrammarConceptOverrideFor("Genetiivi (-n)", "vi"))
	assert.Equal(t, "thì hiện tại", GrammarConceptOverrideFor("Preesens", "vi"))
	assert.Equal(t, "thức mệnh lệnh", GrammarConceptOverrideFor("Imperatiivi", "vi"))
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
	// MUST produce the same VI strings as the legacy DictionaryTermOverride
	// for every Finnish pronoun — this is the no-regression contract that
	// lets us migrate callers without behavior change.
	assert.Equal(t, "tôi", TermOverrideFor("minä", "vi"))
	assert.Equal(t, "bạn", TermOverrideFor("sinä", "vi"))
	assert.Equal(t, "anh ấy/cô ấy", TermOverrideFor("hän", "vi"))
	assert.Equal(t, "nó", TermOverrideFor("se", "vi"))
	assert.Equal(t, "chúng tôi/chúng ta", TermOverrideFor("me", "vi"))
	// "te" is the plural "you" — pre-registry returned "các bạn/quý vị"
	// to preserve the formal/plural form. The new registry has a
	// separate "you (plural)" key for this exact reason.
	assert.Equal(t, "các bạn/quý vị", TermOverrideFor("te", "vi"))
	assert.Equal(t, "họ", TermOverrideFor("he", "vi"))
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
	assert.Equal(t, "tôi", TermOverrideFor("MINÄ", "vi"))
	assert.Equal(t, "anh ấy/cô ấy", TermOverrideFor(" Hän ", "vi"))
}

func TestTermOverrideFor_FiPronounsHaveCorrespondingGlossSeeds(t *testing.T) {
	// Invariant: every FI key in termOverrides MUST appear in
	// finnishPronounToEnglish, AND the English value MUST have a
	// gloss seed (i.e. GlossOverrideFor with locale="en" returns
	// non-empty). Without this, a future seed change in one map
	// silently desyncs the other, and TermOverrideFor starts
	// returning "" for valid pronouns.
	for fi := range termOverrides {
		english, ok := finnishPronounToEnglish[fi]
		if !ok {
			t.Errorf("termOverrides has key %q but finnishPronounToEnglish does not", fi)
			continue
		}
		// Sanity: the English form must round-trip through the
		// gloss registry with a VI seed.
		viGot := GlossOverrideFor(english, "vi")
		if viGot == "" {
			t.Errorf("FI pronoun %q → English %q has no VI gloss seed", fi, english)
		}
		// And it must round-trip with English fallback.
		enGot := GlossOverrideFor(english, "en")
		if enGot == "" {
			t.Errorf("FI pronoun %q → English %q has no EN gloss seed", fi, english)
		}
	}
}

func TestTermOverrideFor_TableInvariant_EveryFiKeyResolvesToItsViValue(t *testing.T) {
	// Invariant: every entry in termOverrides MUST resolve via
	// TermOverrideFor(fi, "vi") to that same value. If this fails,
	// the supportregistry lookup is silently diverging from the
	// hand-curated table.
	for fi, expectedVi := range termOverrides {
		got := TermOverrideFor(fi, "vi")
		assert.Equal(t, expectedVi, got, "FI pronoun %q: table=%q registry=%q", fi, expectedVi, got)
	}
}
