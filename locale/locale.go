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

// NormalizeLearningLanguageCode normalizes a locale-like value to Kielo's
// internal canonical learning-language code. It is intentionally equivalent
// to NormalizeLocaleCode while older call sites are being renamed.
func NormalizeLearningLanguageCode(code string) string {
	return NormalizeLocaleCode(code)
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
	return NormalizeLearningLanguageCode(value)
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
