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
// The contract each function exports:
//   - DictionaryGlossOverride: case-insensitive, trims whitespace,
//     returns "" on miss.
//   - DictionaryTermOverride: same contract, different table.
//   - KnownLemmaOverride: same contract, canonicalizes pronoun lemmas
//     that morphology APIs may not handle correctly.
//   - GrammarConceptFallback: case-SENSITIVE, trims whitespace only.
//     This divergence is intentional: grammar concept names are
//     canonical tokens (e.g. "Genetiivi (-n)"), not free text.

func TestDictionaryGlossOverride_ReturnsCanonicalTranslation(t *testing.T) {
	assert.Equal(t, "tôi", DictionaryGlossOverride("I"))
	assert.Equal(t, "tôi", DictionaryGlossOverride("me"))
	assert.Equal(t, "bạn", DictionaryGlossOverride("you"))
	assert.Equal(t, "anh ấy/cô ấy", DictionaryGlossOverride("he/she"))
	assert.Equal(t, "cửa hàng, tiệm", DictionaryGlossOverride("shop, store"))
}

func TestDictionaryGlossOverride_CaseInsensitive(t *testing.T) {
	// Callers upstream sometimes lowercase, sometimes don't. The
	// override must match regardless so we don't miss "I" vs "i"
	// or "TRAIN" vs "train".
	assert.Equal(t, "tôi", DictionaryGlossOverride("i"))
	assert.Equal(t, "tàu hỏa", DictionaryGlossOverride("TRAIN"))
	assert.Equal(t, "họ", DictionaryGlossOverride("They"))
}

func TestDictionaryGlossOverride_TrimsWhitespace(t *testing.T) {
	// Translator input often has trailing whitespace from JSON parsing.
	assert.Equal(t, "tôi", DictionaryGlossOverride("  I  "))
	assert.Equal(t, "họ", DictionaryGlossOverride("\tthey\n"))
}

func TestDictionaryGlossOverride_EmptyOrMissing(t *testing.T) {
	assert.Equal(t, "", DictionaryGlossOverride(""))
	assert.Equal(t, "", DictionaryGlossOverride("   "))
	assert.Equal(t, "", DictionaryGlossOverride("xyz not a gloss"))
}

func TestDictionaryTermOverride_HandlesFinnishPronouns(t *testing.T) {
	assert.Equal(t, "tôi", DictionaryTermOverride("minä"))
	assert.Equal(t, "bạn", DictionaryTermOverride("sinä"))
	assert.Equal(t, "anh ấy/cô ấy", DictionaryTermOverride("hän"))
	assert.Equal(t, "nó", DictionaryTermOverride("se"))
	assert.Equal(t, "chúng tôi/chúng ta", DictionaryTermOverride("me"))
	assert.Equal(t, "các bạn/quý vị", DictionaryTermOverride("te"))
	assert.Equal(t, "họ", DictionaryTermOverride("he"))
}

func TestDictionaryTermOverride_CaseInsensitiveAndTrimmed(t *testing.T) {
	// Finnish pronouns with diacritics pass through ToLower correctly
	// (Go's strings.ToLower is unicode-aware).
	assert.Equal(t, "tôi", DictionaryTermOverride("MINÄ"))
	assert.Equal(t, "bạn", DictionaryTermOverride(" Sinä "))
}

func TestDictionaryTermOverride_MissingReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", DictionaryTermOverride(""))
	assert.Equal(t, "", DictionaryTermOverride("  "))
	assert.Equal(t, "", DictionaryTermOverride("talo")) // "house", not an override
}

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

func TestGrammarConceptFallback_MapsCanonicalNames(t *testing.T) {
	// Both Finnish (native) and English (canonical) names are
	// supported — callers may pass either depending on where the
	// concept label originated.
	assert.Equal(t, "cách sở hữu", GrammarConceptFallback("Genetiivi (-n)"))
	assert.Equal(t, "cách sở hữu", GrammarConceptFallback("Genitive Case"))
	assert.Equal(t, "thì hiện tại", GrammarConceptFallback("Preesens"))
	assert.Equal(t, "thì hiện tại", GrammarConceptFallback("Present Tense"))
	assert.Equal(t, "thức mệnh lệnh", GrammarConceptFallback("Imperatiivi"))
}

func TestGrammarConceptFallback_IsCaseSensitive(t *testing.T) {
	// UNLIKE the other three functions, GrammarConceptFallback is
	// case-sensitive by design. Concept names are canonical tokens
	// (e.g. "Preesens" is a Finnish proper noun for the tense), not
	// free text, so lowercase variants should NOT match — they
	// likely indicate the caller passed a generic word rather than
	// a concept label.
	assert.Equal(t, "", GrammarConceptFallback("preesens"))
	assert.Equal(t, "", GrammarConceptFallback("PRESENT TENSE"))
	assert.Equal(t, "", GrammarConceptFallback("genetiivi (-n)"))
}

func TestGrammarConceptFallback_TrimsWhitespace(t *testing.T) {
	// TrimSpace applies (line 30 of vietnamese.go). Leading/trailing
	// whitespace from table data or JSON parsing is benign.
	assert.Equal(t, "thì hiện tại", GrammarConceptFallback("  Preesens  "))
	assert.Equal(t, "thì quá khứ", GrammarConceptFallback("\tImperfekti\n"))
}

func TestGrammarConceptFallback_MissingReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", GrammarConceptFallback(""))
	assert.Equal(t, "", GrammarConceptFallback("Not a real concept"))
}

// ----------------------------------------------------------------------------
// ADR-008 supportregistry variants: GlossOverrideFor / GrammarConceptOverrideFor
// ----------------------------------------------------------------------------
//
// These tests pin the per-locale resolution contract that the new
// variants must satisfy. The legacy wrappers above are now thin
// "supportLocale = vi" shims around these — if the variants behave
// correctly for vi the legacy tests above continue passing.

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

func TestTermOverrideFor_MatchesLegacyDictionaryTermOverrideForVi(t *testing.T) {
	// No-regression invariant: for every entry in termOverrides, the
	// new TermOverrideFor(fi, "vi") MUST produce the same string as
	// the legacy DictionaryTermOverride(fi). If this fails, the
	// migration silently changed VI output.
	for fi, expectedVi := range termOverrides {
		got := TermOverrideFor(fi, "vi")
		assert.Equal(t, expectedVi, got, "FI pronoun %q: legacy=%q new=%q", fi, expectedVi, got)
	}
}
