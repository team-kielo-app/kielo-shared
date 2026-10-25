package gemini

import "strings"

// languageCodes is the canonical Kielo language -> BCP-47 tag map for Gemini
// TTS. It mirrors kielo_shared/seam/tts/languages.py; both are tested against
// testdata/language_tags.json.
var languageCodes = map[string]string{
	"fi": "fi-FI", "sv": "sv-SE", "en": "en-US", "et": "et-EE", "de": "de-DE",
	"fr": "fr-FR", "es": "es-ES", "vi": "vi-VN", "zh": "cmn-CN",
}

// LanguageCodes returns a copy of the canonical language -> tag map.
func LanguageCodes() map[string]string {
	out := make(map[string]string, len(languageCodes))
	for k, v := range languageCodes {
		out[k] = v
	}
	return out
}

// LanguageTag maps a bare code through the canonical map; a tag with a region
// passes through (underscores become hyphens); an unknown bare code is returned
// unchanged.
func LanguageTag(language string) string {
	base := strings.ReplaceAll(strings.TrimSpace(language), "_", "-")
	if strings.Contains(base, "-") {
		return base
	}
	if tag, ok := languageCodes[strings.ToLower(base)]; ok {
		return tag
	}
	return base
}
