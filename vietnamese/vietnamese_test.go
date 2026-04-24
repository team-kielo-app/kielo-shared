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
