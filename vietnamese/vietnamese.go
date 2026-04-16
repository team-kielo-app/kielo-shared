// Package vietnamese provides hardcoded Vietnamese translation overrides
// for common Finnish learning terms. These are zero-latency fallbacks used
// when the translation API is unavailable or for high-frequency terms that
// benefit from hand-verified translations.
package vietnamese

import "strings"

// DictionaryGlossOverride returns a Vietnamese translation for a common
// English gloss (e.g. "I" → "tôi"), or "" if no override exists.
func DictionaryGlossOverride(value string) string {
	return glossOverrides[strings.ToLower(strings.TrimSpace(value))]
}

// DictionaryTermOverride returns a Vietnamese translation for a common
// Finnish pronoun/term (e.g. "minä" → "tôi"), or "" if no override exists.
func DictionaryTermOverride(term string) string {
	return termOverrides[strings.ToLower(strings.TrimSpace(term))]
}

// KnownLemmaOverride returns the canonical lemma for Finnish pronouns
// that morphology APIs may not handle correctly, or "" if not a known override.
func KnownLemmaOverride(term string) string {
	return knownLemmas[strings.ToLower(strings.TrimSpace(term))]
}

// GrammarConceptFallback returns a Vietnamese translation for a grammar
// concept name (Finnish or English), or "" if no override exists.
func GrammarConceptFallback(value string) string {
	return grammarOverrides[strings.TrimSpace(value)]
}

var glossOverrides = map[string]string{
	"i":                "tôi",
	"me":               "tôi",
	"you":              "bạn",
	"for you / to you": "cho bạn",
	"he/she":           "anh ấy/cô ấy",
	"he / she":         "anh ấy/cô ấy",
	"it":               "nó",
	"we":               "chúng tôi/chúng ta",
	"they":             "họ",
	"to be":            "là",
	"shop, store":      "cửa hàng, tiệm",
	"train":            "tàu hỏa",
}

var termOverrides = map[string]string{
	"minä": "tôi",
	"sinä": "bạn",
	"hän":  "anh ấy/cô ấy",
	"se":   "nó",
	"me":   "chúng tôi/chúng ta",
	"te":   "các bạn/quý vị",
	"he":   "họ",
}

var knownLemmas = map[string]string{
	"minä": "minä",
	"sinä": "sinä",
	"hän":  "hän",
	"se":   "se",
	"me":   "me",
	"te":   "te",
	"he":   "he",
}

var grammarOverrides = map[string]string{
	"Genetiivi (-n)":  "cách sở hữu",
	"Genitive Case":   "cách sở hữu",
	"Genitive":        "sở hữu",
	"Partitiivi":      "cách bộ phận",
	"Partitive Case":  "cách bộ phận",
	"Imperatiivi":     "thức mệnh lệnh",
	"Imperative Mood": "thức mệnh lệnh",
	"Preesens":        "thì hiện tại",
	"Present Tense":   "thì hiện tại",
	"Perfekti":        "thì hoàn thành",
	"Perfect Tense":   "thì hoàn thành",
	"Imperfekti":      "thì quá khứ",
	"Past Tense":      "thì quá khứ",
}
