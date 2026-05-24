package locale

import "strings"

// TierASupportLocale is the default support language for the platform.
// English is the universal fallback support language for hints, glosses,
// explanations, etc.
const TierASupportLocale = "en"

// Phase 10C: LegacyDefaultLearningLanguage const was DELETED in the
// "eliminate silent fi fallback" sweep across the monorepo. Every
// previous call site has been either:
//   - converted to error-return on empty input (resolver-side strict
//     gates: requireLearningLanguageCode, CmsLangTable, resolveKTVWorkflowLanguage,
//     resolveGenerateScenarioLearningLanguage, callMorphologyAPI),
//   - replaced with bare "fi" literal where the intent IS specifically
//     Finnish (e.g. finnishOnlyTranslationFallbacks gate in
//     ktv_workflow_handler.go, fi-only default source URL in
//     ktv_vocabulary_importer.go),
//   - or replaced with empty-output (display helpers like ktv_locale.go
//     LanguageNameForPrompt where empty makes the misshaped caller
//     visible in the rendered output).
//
// Adding a new "default learning language" notion back should require
// explicit ADR + grep audit; the previous indirection let drift
// accumulate silently.

var supportedLearningLanguages = map[string]struct{}{
	"fi": {},
	"sv": {},
}

// SupportedLearningLanguages returns the canonical learning-content language
// codes the platform currently authors content for, sorted lexicographically
// for deterministic output. Callers that need to fan out work across every
// per-language schema (cms_<lang>, klearn_<lang>) should source the list
// from here rather than hardcoding it — adding a new language only updates
// the supportedLearningLanguages map above and contract tests pick up the
// rest.
func SupportedLearningLanguages() []string {
	codes := make([]string, 0, len(supportedLearningLanguages))
	for code := range supportedLearningLanguages {
		codes = append(codes, code)
	}
	// Sort in-place for determinism without pulling sort into this small file.
	for i := 1; i < len(codes); i++ {
		for j := i; j > 0 && codes[j-1] > codes[j]; j-- {
			codes[j-1], codes[j] = codes[j], codes[j-1]
		}
	}
	return codes
}

// NormalizeLocaleCode normalizes any locale-like value to Kielo's internal
// canonical language code: base language only, lowercase. Region/script
// subtags are intentionally discarded; provider-specific locale tags must be
// derived at the provider boundary, not stored or propagated internally.
func NormalizeLocaleCode(code string) string {
	code = strings.TrimSpace(strings.ReplaceAll(code, "_", "-"))
	if code == "" {
		return ""
	}
	base, _, _ := strings.Cut(code, "-")
	base = strings.ToLower(strings.TrimSpace(base))
	if base == "vn" {
		return "vi"
	}
	return base
}

// NormalizeLearningLanguageCode normalizes locale-like input and returns it
// only when Kielo currently has authored learning content for that language.
// Use NormalizeLocaleCode/BaseLocale for support and localization languages.
func NormalizeLearningLanguageCode(code string) string {
	normalized := NormalizeLocaleCode(code)
	if _, ok := supportedLearningLanguages[normalized]; ok {
		return normalized
	}
	return ""
}

// IsSupportedLearningLanguage reports whether code is currently an authored
// learning-content language. Localization/support locales are broader; do not
// use this for UI or notification language selection.
func IsSupportedLearningLanguage(code string) bool {
	return NormalizeLearningLanguageCode(code) != ""
}

// NormalizeSupportedLearningLanguageCode is an explicit alias retained for
// call sites where spelling out the supported-content contract improves
// readability.
func NormalizeSupportedLearningLanguageCode(code string) string {
	return NormalizeLearningLanguageCode(code)
}

// NormalizeSourceLocale normalizes source-language values to the same
// base-only internal standard as every other Kielo language field.
func NormalizeSourceLocale(code string) string {
	return NormalizeLocaleCode(code)
}

// NormalizeAcceptLanguage normalizes a value that may be either a plain
// language code or an Accept-Language header (comma-separated with quality
// values). It extracts the first tag and collapses it to a base code.
func NormalizeAcceptLanguage(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	first, _, _ := strings.Cut(value, ",")
	tag, _, _ := strings.Cut(first, ";")
	return NormalizeLocaleCode(tag)
}

// BaseLocale returns the normalized base language code for any locale-like input.
func BaseLocale(value string) string {
	return NormalizeLocaleCode(value)
}

// languageDisplayNames maps Kielo's canonical base language codes to their
// English display names. Mirrors LANGUAGE_DISPLAY_NAMES in the Python
// kielo_shared.locale_constants module — both must list the same set so a
// service can't accidentally drop to a generic placeholder ("learning-language")
// when handling a locale that the platform officially supports. Add new
// locales here, not in per-feature maps. Keys are normalized base codes.
var languageDisplayNames = map[string]string{
	"ar": "Arabic",
	"bn": "Bengali",
	"de": "German",
	"en": "English",
	"es": "Spanish",
	"fi": "Finnish",
	"fr": "French",
	"hi": "Hindi",
	"hu": "Hungarian",
	"it": "Italian",
	"ja": "Japanese",
	"ko": "Korean",
	"nl": "Dutch",
	"pl": "Polish",
	"pt": "Portuguese",
	"ru": "Russian",
	"sr": "Serbian",
	"sv": "Swedish",
	"th": "Thai",
	"tr": "Turkish",
	"uk": "Ukrainian",
	"vi": "Vietnamese",
	"zh": "Chinese",
}

// IsSupportedSupportLanguage reports whether code is one of the platform's
// recognized UI / support-language codes. Use this to gate user input on
// /me/device-preferences and similar endpoints — a code outside this set
// has no DisplayName, no support content, and would eventually surface as
// a generic placeholder in the mobile UI. Validate at the API boundary
// so bad input gets a 4xx instead of a silent stale-display state.
func IsSupportedSupportLanguage(code string) bool {
	normalized := NormalizeLocaleCode(code)
	if normalized == "" {
		return false
	}
	_, ok := languageDisplayNames[normalized]
	return ok
}

// AllSupportLocales returns the platform's full set of support-locale
// codes (the keyset of languageDisplayNames), sorted lexicographically.
//
// Use as the seed-locale list for supportregistry.New(...) when the
// registry is meant to cover every locale the platform officially
// supports. Domain-curated subsets (e.g. comms-service's "we only have
// email templates for {en, fi, sv, vi}") should keep their hand-written
// slice — adding a new platform locale doesn't automatically mean
// authoring new emails for it.
//
// Adding a new locale = adding one entry to languageDisplayNames above.
// Every caller of AllSupportLocales picks it up automatically.
func AllSupportLocales() []string {
	codes := make([]string, 0, len(languageDisplayNames))
	for code := range languageDisplayNames {
		codes = append(codes, code)
	}
	for i := 1; i < len(codes); i++ {
		for j := i; j > 0 && codes[j-1] > codes[j]; j-- {
			codes[j-1], codes[j] = codes[j], codes[j-1]
		}
	}
	return codes
}

// DisplayName returns the English display name for any locale-like input
// ("vi", "vi-VN", "vn" — all produce "Vietnamese"). Falls back to the
// supplied fallback (or the normalized code itself when fallback is empty)
// when the code isn't in the canonical map. Never returns an empty string
// for non-empty input.
//
// Use in places that name the learner's language to humans: LLM prompts
// ("You are a {language} dictionary assistant..."), admin UI labels, log
// fields. Single source of truth so a service can't accidentally drop to a
// generic placeholder when handling a locale the platform officially supports.
func DisplayName(code, fallback string) string {
	normalized := NormalizeLocaleCode(code)
	if normalized == "" {
		return fallback
	}
	if name, ok := languageDisplayNames[normalized]; ok {
		return name
	}
	if fallback != "" {
		return fallback
	}
	return normalized
}

// SupportLocaleCandidates returns the canonical lookup chain for support
// content using base-only language codes. It prefers the requested language
// and falls back to English.
func SupportLocaleCandidates(requested string) []string {
	normalized := NormalizeLocaleCode(requested)
	if normalized == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	appendUnique := func(value string) {
		value = NormalizeLocaleCode(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	appendUnique(normalized)
	if normalized != TierASupportLocale {
		appendUnique(TierASupportLocale)
	}
	return out
}
