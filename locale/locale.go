package locale

import "strings"

const TierASupportLocale = "en"

// NormalizeLocaleCode normalizes a locale code to BCP 47 format.
// It lowercases the base language, uppercases 2-3 char region subtags,
// titlecases 4-char script subtags, replaces underscores with hyphens,
// and maps the legacy "vn" alias to "vi" (Vietnamese).
func NormalizeLocaleCode(code string) string {
	code = strings.TrimSpace(strings.ReplaceAll(code, "_", "-"))
	if code == "" {
		return ""
	}
	parts := strings.Split(code, "-")
	for i := range parts {
		part := strings.TrimSpace(parts[i])
		switch {
		case i == 0:
			base := strings.ToLower(part)
			if base == "vn" {
				base = "vi"
			}
			parts[i] = base
		case len(part) == 2 || len(part) == 3:
			parts[i] = strings.ToUpper(part)
		case len(part) == 4:
			parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
		default:
			parts[i] = strings.ToLower(part)
		}
	}
	return strings.Join(parts, "-")
}

// NormalizeLearningLanguageCode normalizes a locale code and returns only
// the base language component (e.g. "sv-SE" → "sv", "vi_VN" → "vi").
func NormalizeLearningLanguageCode(code string) string {
	normalized := NormalizeLocaleCode(code)
	if normalized == "" {
		return ""
	}
	return strings.Split(normalized, "-")[0]
}

// NormalizeAcceptLanguage normalizes a value that may be either a plain
// locale code or an Accept-Language header (comma-separated with quality
// values). It extracts the first (highest priority) language tag and
// normalizes it.
func NormalizeAcceptLanguage(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	first := strings.SplitN(value, ",", 2)[0]
	tag := strings.SplitN(first, ";", 2)[0]
	return NormalizeLocaleCode(tag)
}

// BaseLocale returns the normalized base language subtag for any locale-like input.
func BaseLocale(value string) string {
	return NormalizeLearningLanguageCode(value)
}

// SupportLocaleCandidates returns the canonical lookup chain for support-language
// content. It prefers the requested locale, then its base locale, and finally
// English as the Tier A support locale when the requested locale is not already
// English.
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
	appendUnique(BaseLocale(normalized))
	if BaseLocale(normalized) != TierASupportLocale && normalized != TierASupportLocale {
		appendUnique(TierASupportLocale)
	}
	return out
}
