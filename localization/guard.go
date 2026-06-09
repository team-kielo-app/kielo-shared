package localization

import (
	"regexp"
	"strings"
)

// CanonicalGuard is the Go port of the Sweep PP/QQ/KKK suspicious-
// translation guard, lifted from kielo-content-service mindmap_localizer
// to kielo-shared in Round 10D so every Go service that wires the seam
// gets the canonical quality check without copy-pasting the rules.
//
// Cross-language parity with the Python canonical at
// kielolearn-engine ContentLocalizer._is_suspicious_translation
// is maintained by the contract test
// tests/contract/suspicious_translation_truth_table_test.go which
// reads the Python-emitted JSON fixture at
// scripts/suspicious-translation-fixtures.json.
//
// Rules ported (Python rule numbers in parens):
//
//	R1  empty translation
//	R2  template-leakage chars (% or _ in output)
//	R3a short-output frequency check (6..59 tokens; max-count >= 3;
//	    unique <= total/2)
//	R3b consecutive-run check (any size; 4+ identical adjacent tokens)
//	R4  length blow-up (source <= 40 chars; output > 70 chars)
//	R5  severe content-token truncation on title-class inputs
//	    (4+ content tokens collapsing to <= 1/3 target tokens after
//	    function-word filter + parenthetical strip)
//	R6  non-source-shaped junk symbols (music notes, geometric shapes,
//	    box drawing, private-use area, replacement char) in output but
//	    not in source. Round 10D ADDED to shared guard.
//	R7  negation-injection on title-class inputs (target locale strong
//	    negation marker present in output, no negation hint in source).
//	    Round 10D ADDED to shared guard.
//
// Rules NOT ported (Python-only, documented at content_localizer.py
// "Sweep KKK Pattern" comment):
//
//	(1)  vi-specific LLM apology markers — rare in production post-
//	     Sweep EEE routing.
//	R5b  single-source-token single-char target — niche fix for an
//	     opus-mt-en-vi degenerate pattern that doesn't recur on Gemini.
//
// Implementations of SuspiciousTranslationGuard from outside kielo-
// shared are free to layer their own additional rules on top of
// CanonicalGuard; the seam protocol just asks for a boolean verdict.
type CanonicalGuard struct{}

// NewCanonicalGuard returns a CanonicalGuard wired with the canonical
// rule set. The struct has no state; callers can reuse one instance
// across goroutines.
func NewCanonicalGuard() CanonicalGuard {
	return CanonicalGuard{}
}

// IsSuspicious implements SuspiciousTranslationGuard.
//
// Returns true when the candidate translation matches a known failure
// mode and should be discarded (the seam falls back to source text).
// Each rule is a CONSERVATIVE filter: false-negative bias (better to
// pass a marginal bad translation than reject a good one).
//
//nolint:gocyclo,gocognit,funlen // Mirrors the shared suspicious-translation truth-table as explicit ordered guard rules.
func (CanonicalGuard) IsSuspicious(sourceText, candidate, targetLocale string) bool {
	source := strings.TrimSpace(sourceText)
	translated := strings.TrimSpace(candidate)

	// R1: empty
	if translated == "" {
		return true
	}
	lowered := strings.ToLower(translated)

	// R2: template-leakage chars
	if strings.ContainsAny(translated, "%_") {
		return true
	}

	tokens := strings.Fields(lowered)

	// R3a: short-output frequency
	if len(tokens) >= 6 && len(tokens) < 60 {
		counts := make(map[string]int)
		maxCount := 0
		for _, token := range tokens {
			counts[token]++
			if counts[token] > maxCount {
				maxCount = counts[token]
			}
		}
		if maxCount >= 3 && len(counts) <= len(tokens)/2 {
			return true
		}
	}

	// R3b: consecutive-run check (any size; 4+ identical adjacent)
	if len(tokens) >= 4 {
		var runToken string
		runLength := 0
		for _, token := range tokens {
			if token == runToken {
				runLength++
				if runLength >= 4 {
					return true
				}
			} else {
				runToken = token
				runLength = 1
			}
		}
	}

	// R4: length blow-up
	if len([]rune(source)) <= 40 && len([]rune(translated)) > 70 {
		return true
	}

	// R5: severe content-token truncation on title-class inputs
	sourceTokens := strings.Fields(strings.ToLower(source))
	isTitleClass := len(sourceTokens) >= 1 && len(sourceTokens) <= 5
	if isTitleClass {
		sourceForR5 := strings.TrimSpace(guardParenStripPattern.ReplaceAllString(source, ""))
		sourceR5Tokens := strings.Fields(strings.ToLower(sourceForR5))
		contentCount := 0
		for _, t := range sourceR5Tokens {
			if _, isFn := guardEnFunctionWords[t]; !isFn {
				contentCount++
			}
		}
		if contentCount >= 4 && len(tokens) > 0 && len(tokens)*3 <= contentCount {
			return true
		}
	}

	// R6: non-source-shaped junk symbols. Round 10D ADDED.
	if guardHasJunkSymbol(translated) && !guardHasJunkSymbol(source) {
		return true
	}

	// R7: negation-injection on title-class. Round 10D ADDED.
	if isTitleClass {
		if markers, ok := guardNegationMarkers[strings.ToLower(targetLocale)]; ok {
			for _, marker := range markers {
				if strings.Contains(lowered, marker) {
					sourceLowered := strings.ToLower(source)
					hasSourceHint := false
					for _, hint := range guardSourceNegationHints {
						if strings.Contains(sourceLowered, hint) {
							hasSourceHint = true
							break
						}
					}
					if !hasSourceHint {
						return true
					}
				}
			}
		}
	}

	return false
}

// guardParenStripPattern strips parenthetical content from source text
// before R5 computes content-token ratio. Mirrors the Python canonical's
// _PAREN_RE.
var guardParenStripPattern = regexp.MustCompile(`\([^)]*\)`)

// guardEnFunctionWords is the canonical English function-word filter
// used by R5. Keeps R5 from rejecting phrasal verbs and short idioms
// whose source tokens are function words ("a long time" → "lâu").
// Byte-equivalent to the Python canonical's _EN_FUNCTION_WORDS and the
// kielo-content-service kielotv copy this round retires.
var guardEnFunctionWords = map[string]struct{}{
	// Articles
	"a": {}, "an": {}, "the": {},
	// Prepositions / particles
	"of": {}, "in": {}, "on": {}, "at": {}, "to": {}, "for": {},
	"with": {}, "by": {}, "from": {},
	"up": {}, "down": {}, "out": {}, "off": {}, "over": {}, "under": {},
	"into": {}, "onto": {}, "upon": {}, "about": {}, "after": {}, "before": {},
	"away": {}, "back": {}, "through": {}, "across": {}, "along": {},
	"around": {}, "between": {}, "behind": {},
	// Auxiliaries
	"is": {}, "are": {}, "was": {}, "were": {},
	"be": {}, "been": {}, "being": {},
	// Coordinators
	"and": {}, "or": {}, "but": {}, "so": {},
}

// guardNegationMarkers contains the strong negation cues per locale
// that R7 uses to detect spurious negation injection. Keys are base
// locale codes (lowercase); values are substring patterns (also
// lowercase) checked against the translated output.
//
// Mirrors the Python canonical's _NEGATION_MARKERS. Adding a new
// target locale = add an entry here AND a regression test exercising
// the new locale's known opus-mt/Gemini negation failure mode.
var guardNegationMarkers = map[string][]string{
	"vi": {"không có gì", "không có", "không bao giờ"},
	"en": {"nothing", "never", "no longer"},
	"fi": {"ei mitään", "ei koskaan"},
	"sv": {"ingenting", "aldrig"},
}

// guardSourceNegationHints are the source-side cues that prove the
// English source genuinely contains a negation, suppressing R7 from
// firing on legitimate negation translation.
//
// Mirrors the Python canonical's _SOURCE_NEGATION_HINTS.
var guardSourceNegationHints = []string{
	"no ", "not ", "n't",
	"never", "nothing", "none", "without",
	"ei ", "inte ", "icke ",
}

// guardHasJunkSymbol returns true when s contains any character in the
// known-junk Unicode ranges (music symbols, geometric shapes, box-
// drawing, private-use, replacement char). Emoji are deliberately NOT
// junk — they appear in legitimate titles ("🎉 Welcome").
//
// Mirrors the Python canonical's _JUNK_RANGES + _has_junk.
func guardHasJunkSymbol(s string) bool {
	for _, ch := range s {
		cp := int(ch)
		// Musical symbols
		if cp >= 0x2669 && cp <= 0x266F {
			return true
		}
		if cp >= 0x1D100 && cp <= 0x1D1FF {
			return true
		}
		// Misc symbols (☀☁☂...) — covers geometric shapes too
		if cp >= 0x2600 && cp <= 0x26FF {
			return true
		}
		// Box drawing
		if cp >= 0x2500 && cp <= 0x257F {
			return true
		}
		// Private-use area (decoder artifacts)
		if cp >= 0xE000 && cp <= 0xF8FF {
			return true
		}
		// Replacement char (decode failure)
		if cp == 0xFFFD {
			return true
		}
	}
	return false
}
