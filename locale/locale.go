package locale

import "strings"

// TierASupportLocale is the default support language for the platform.
// English is the universal fallback support language for hints, glosses,
// explanations, etc.
const TierASupportLocale = "en"

// LegacyDefaultLearningLanguage is the default learning language for legacy
// data where learning_language_code is NULL or missing. Finnish is the
// original/default learning language of the platform.
const LegacyDefaultLearningLanguage = "fi"

var supportedLearningLanguages = map[string]struct{}{
	"fi": {},
	"sv": {},
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
