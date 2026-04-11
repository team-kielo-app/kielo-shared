package locale

import "strings"

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
