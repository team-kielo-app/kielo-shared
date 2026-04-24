package locale

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeLocaleCode(t *testing.T) {
	assert.Equal(t, "vi", NormalizeLocaleCode(" vn "))
	assert.Equal(t, "vi-VN", NormalizeLocaleCode("vi_VN"))
	assert.Equal(t, "sv-SE", NormalizeLocaleCode("sv-SE"))
	assert.Equal(t, "sv-SE", NormalizeLocaleCode("sv_se"))
	assert.Equal(t, "vi-VN", NormalizeLocaleCode("vn_vn"))
	assert.Equal(t, "zh-Hant-TW", NormalizeLocaleCode("zh-Hant-TW"))
	assert.Equal(t, "pt-BR", NormalizeLocaleCode(" pt_BR "))
	assert.Equal(t, "", NormalizeLocaleCode(""))
	assert.Equal(t, "", NormalizeLocaleCode("  "))
}

func TestNormalizeLearningLanguageCode(t *testing.T) {
	assert.Equal(t, "vi", NormalizeLearningLanguageCode(" vn "))
	assert.Equal(t, "vi", NormalizeLearningLanguageCode("vi_VN"))
	assert.Equal(t, "sv", NormalizeLearningLanguageCode("sv-SE"))
	assert.Equal(t, "sv", NormalizeLearningLanguageCode("sv_SE"))
	assert.Equal(t, "", NormalizeLearningLanguageCode(""))
}

func TestNormalizeAcceptLanguage(t *testing.T) {
	assert.Equal(t, "pt-BR", NormalizeAcceptLanguage(" pt_BR "))
	assert.Equal(t, "zh-Hant-TW", NormalizeAcceptLanguage("zh-Hant-TW,zh;q=0.9"))
	assert.Equal(t, "vi", NormalizeAcceptLanguage(" vn "))
	assert.Equal(t, "vi-VN", NormalizeAcceptLanguage("vi_VN"))
	assert.Equal(t, "de-DE", NormalizeAcceptLanguage("de-DE,de;q=0.9"))
	assert.Equal(t, "", NormalizeAcceptLanguage(""))
}

func TestSupportLocaleCandidates(t *testing.T) {
	assert.Equal(t, []string{"vi-VN", "vi", "en"}, SupportLocaleCandidates("vi_VN"))
	assert.Equal(t, []string{"pt-BR", "pt", "en"}, SupportLocaleCandidates(" pt_BR "))
	assert.Equal(t, []string{"en-US", "en"}, SupportLocaleCandidates("en_US"))
	assert.Nil(t, SupportLocaleCandidates(""))
}

// TestSupportLocaleCandidates_EdgeCases pins dedup and Tier-A-fallback
// behavior for shapes the main test didn't cover. These are the
// invariants callers (LocalizationService.ResolveTemplate, mobile-bff
// support-language resolver, email locale router) rely on to avoid
// double-querying the translations table for the same code, or
// double-appending English to the candidate list.
func TestSupportLocaleCandidates_EdgeCases(t *testing.T) {
	// Bare English: must NOT double-append — ["en"] not ["en", "en"].
	// Would otherwise cause duplicate getApprovedTranslation calls
	// for the same key_id + language_code pair.
	assert.Equal(t, []string{"en"}, SupportLocaleCandidates("en"))

	// Bare non-English base: 2-tier chain (self, then en). Since the
	// base equals the normalized form, dedup collapses the middle
	// entry, leaving [base, en].
	assert.Equal(t, []string{"sv", "en"}, SupportLocaleCandidates("sv"))

	// Legacy 'vn' alias canonicalizes to 'vi' before fanout.
	assert.Equal(t, []string{"vi", "en"}, SupportLocaleCandidates("vn"))
	assert.Equal(t, []string{"vi-VN", "vi", "en"}, SupportLocaleCandidates("vn_vn"))

	// Mixed-case input normalizes cleanly through the whole chain.
	assert.Equal(t, []string{"sv-SE", "sv", "en"}, SupportLocaleCandidates("SV_se"))

	// Script subtag zh-Hant-TW: base is zh, full locale preserved at
	// position 0, en terminates the chain. Exercises the multi-subtag
	// path through NormalizeLocaleCode.
	candidates := SupportLocaleCandidates("zh-Hant-TW")
	assert.Equal(t, "zh-Hant-TW", candidates[0])
	assert.Equal(t, "zh", candidates[1])
	assert.Equal(t, "en", candidates[len(candidates)-1])
}

// TestBaseLocale pins the behavior of the alias exported for
// readability. Callers use BaseLocale when they mean "language subtag
// only, not the full locale" — renaming or altering this must not
// change semantics.
func TestBaseLocale(t *testing.T) {
	assert.Equal(t, "sv", BaseLocale("sv-SE"))
	assert.Equal(t, "vi", BaseLocale("vi_VN"))
	assert.Equal(t, "vi", BaseLocale("vn"))
	assert.Equal(t, "en", BaseLocale("en-US"))
	assert.Equal(t, "", BaseLocale(""))
	assert.Equal(t, "", BaseLocale("  "))
}
