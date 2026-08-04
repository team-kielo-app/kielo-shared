package locale

import "testing"

// realWorldSpellings are locale strings clients actually send whose language
// Kielo supports. Every one must normalize to a supported canonical code.
//
// The stakes are higher than a display-name lookup:
// localization.dynamic_translations.language_code is a foreign key onto
// localization.languages, so a code that fails to fold makes the translation
// cache write fail. That write is fail-soft, so nothing surfaces to the user —
// the translation is served, never cached, and re-translated on every
// subsequent request forever, because the locale can never become valid.
// Prod hit this with "ars" while "ar-SA" worked.
var realWorldSpellings = map[string]string{
	// ISO 639-2/T and 639-2/B — the shape that was entirely unhandled.
	"eng": "en", "spa": "es", "deu": "de", "ger": "de", "fra": "fr",
	"fre": "fr", "zho": "zh", "chi": "zh", "ara": "ar", "rus": "ru",
	"jpn": "ja", "kor": "ko", "hin": "hi", "ben": "bn", "tur": "tr",
	"ukr": "uk", "swe": "sv", "fin": "fi", "ita": "it", "pol": "pl",
	"srp": "sr", "tha": "th", "vie": "vi", "nld": "nl", "dut": "nl",
	"por": "pt", "hun": "hu",

	// Macrolanguage members observed or plausible from real devices.
	"arb": "ar", "ars": "ar", "cmn": "zh",

	// Region/script/underscore shapes that already worked — pinned so a
	// future alias change cannot regress them.
	"zh-Hans": "zh", "zh-Hant": "zh", "sr-Latn": "sr", "pt-BR": "pt",
	"es-419": "es", "ar-SA": "ar", "en_US": "en", "vi-VN": "vi",
	"vn": "vi",
}

func TestRealWorldSpellingsFoldToSupportedCodes(t *testing.T) {
	for input, wantBase := range realWorldSpellings {
		if !IsSupportedSupportLanguage(wantBase) {
			t.Fatalf("test bug: expected base %q is not in the supported set", wantBase)
		}
		got := NormalizeLocaleCode(input)
		if got != wantBase {
			t.Errorf("NormalizeLocaleCode(%q) = %q, want %q", input, got, wantBase)
		}
		if !IsSupportedSupportLanguage(input) {
			t.Errorf("IsSupportedSupportLanguage(%q) = false; the translation cache "+
				"write would be rejected by the languages foreign key and the "+
				"paragraph would be re-translated on every request", input)
		}
	}
}

// Folding must not invent support. A code for a language Kielo has no content
// for has to keep reporting false, so callers fall back to English instead of
// translating into a locale that cannot be persisted.
func TestUnsupportedLanguagesAreNotSilentlyFolded(t *testing.T) {
	// cs and fa were both observed failing the dynamic_translations write in
	// prod. They are genuinely unsupported — the fix for them is to stop
	// doing the translation work, NOT to alias them onto something else.
	for _, code := range []string{"cs", "ces", "cze", "fa", "fas", "per", "et", "est", "he", "id"} {
		if IsSupportedSupportLanguage(code) {
			t.Errorf("IsSupportedSupportLanguage(%q) = true; folding must not "+
				"claim support for a language with no authored content", code)
		}
	}
}

// NormalizeLocaleCode also feeds NormalizeLearningLanguageCode, so widening it
// must not widen ADR-001's strict learning-language contract. Folding a code
// onto a language we teach is correct ("fin" IS Finnish); folding one onto a
// support-only language must still be rejected for learning.
func TestLearningLanguageContractNotWidened(t *testing.T) {
	for in, want := range map[string]string{"fin": "fi", "swe": "sv", "fi": "fi", "sv": "sv"} {
		if got := NormalizeLearningLanguageCode(in); got != want {
			t.Errorf("NormalizeLearningLanguageCode(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"eng", "en", "ara", "ars", "zho", "und", "xx"} {
		if got := NormalizeLearningLanguageCode(in); got != "" {
			t.Errorf("NormalizeLearningLanguageCode(%q) = %q; want \"\" — only "+
				"authored learning languages may pass, aliasing must not widen ADR-001", in, got)
		}
	}
}

// The alias table must only ever point at codes that really are supported,
// otherwise a typo would route a valid locale onto a dead one.
func TestAliasTargetsAreAllSupported(t *testing.T) {
	if len(languageCodeAliases) == 0 {
		t.Fatal("alias table is empty; this test would pass vacuously")
	}
	for from, to := range languageCodeAliases {
		if !IsSupportedSupportLanguage(to) {
			t.Errorf("alias %q -> %q: target is not a supported language", from, to)
		}
		if from == to {
			t.Errorf("alias %q -> %q is a no-op", from, to)
		}
	}
}
