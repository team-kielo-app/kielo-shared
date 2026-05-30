// Sweep EEE (2026-05-30) — canonical translator-routing decision
// (Go SSOT, shared across kielo-content-service + kielo-convo +
// kielo-communications-service via the kielo-shared/translation
// Client).
//
// Mirrors the Python source-of-truth in:
//
//	kielolearn-engine/src/kielolearnengine/services/translator_routing.py
//
// The cross-language contract test in
// `kielo-content-service/internal/platform/translation/routing_contract_test.go`
// asserts the Go decision matches the Python decision row-for-row.
// kielo-content-service's local routing.go is now a thin re-export
// of this package so the entire Go monorepo shares ONE routing
// decision function.
//
// See the Python docstring for the empirical rationale (Sweep DDD
// AGENTS.md row + `sample_sentence.py` study).
//
// Architectural note: this package is "shared" but its Gemini
// dispatch goes via an HTTP call to kielolearn-engine
// `/internal/translate-batch`. That's a mild layering inversion
// (shared library calling an application service) — accepted
// deliberately because the engine endpoint is acting as a routing
// dispatcher, not as application logic. If the coupling becomes
// painful, the engine handler can split into a thin standalone
// translation-router service without changing this package's API.
package translation

import (
	"strings"
	"unicode"
)

// Backend selects which translation upstream to dispatch to.
type Backend int

const (
	// BackendPassthrough means "don't translate at all" — src==tgt or
	// one side empty. Caller returns the source text unchanged.
	BackendPassthrough Backend = iota
	// BackendOpusMT routes through kielo-models `/api/v3/translations`
	// (fast, local, deterministic). Used for high-quality pairs with
	// long-enough input that opus-mt's sentence-context output is
	// competitive with Gemini.
	BackendOpusMT
	// BackendGemini routes through kielolearn-engine
	// `/internal/translate-batch` LLM endpoint. Used for short input
	// (where opus-mt fails) or for pairs opus-mt doesn't host
	// natively at acceptable quality.
	BackendGemini
)

// String makes Backend pretty-print in logs/errors. The values mirror
// the Python `Backend(enum.Enum)` string values so contract-test
// failure messages are cross-language readable.
func (b Backend) String() string {
	switch b {
	case BackendPassthrough:
		return "passthrough"
	case BackendOpusMT:
		return "opus_mt"
	case BackendGemini:
		return "gemini"
	default:
		return "unknown"
	}
}

// opusMTHighQualityPairs — pairs where opus-mt is empirically
// competitive with Gemini on sentence-context input. MUST equal the
// Python `OPUS_MT_HIGH_QUALITY_PAIRS` set. The contract test pins
// this.
var opusMTHighQualityPairs = map[[2]string]struct{}{
	{"en", "fi"}: {},
	{"fi", "en"}: {},
	{"en", "sv"}: {},
	{"sv", "en"}: {},
}

// ShortInputTokenThreshold is the token-count cutoff below which we
// route through Gemini regardless of pair. Mirrors the Python
// `SHORT_INPUT_TOKEN_THRESHOLD`. The Python docstring explains the
// empirical rationale.
const ShortInputTokenThreshold = 5

// NSourceTokens counts word tokens in a single source text.
//
// Locale-agnostic — uses Unicode letter+digit runs so Finnish `että`,
// Swedish `är`, Vietnamese `được` all count as one token each.
// Punctuation and whitespace are not tokens.
//
// Mirrors the Python `n_source_tokens`. Go's unicode.IsLetter /
// IsDigit produce the same word-boundary classification as Python's
// `\w` with `re.UNICODE`.
func NSourceTokens(text string) int {
	if text == "" {
		return 0
	}
	count := 0
	inToken := false
	for _, r := range text {
		isWordChar := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
		if isWordChar {
			if !inToken {
				count++
				inToken = true
			}
		} else {
			inToken = false
		}
	}
	return count
}

// NSourceTokensMin returns the MIN token count across a batch. See
// the Python `n_source_tokens_min` docstring for the rationale (a
// batch's safe routing is gated by its shortest item).
//
// Returns 0 for an empty batch (callers should short-circuit).
func NSourceTokensMin(texts []string) int {
	if len(texts) == 0 {
		return 0
	}
	minVal := NSourceTokens(texts[0])
	for _, t := range texts[1:] {
		n := NSourceTokens(t)
		if n < minVal {
			minVal = n
		}
	}
	return minVal
}

// SelectTranslator returns the canonical backend dispatch decision.
//
// Decision priority (top wins):
//  1. Empty src or tgt              → BackendPassthrough
//  2. src == tgt                    → BackendPassthrough
//  3. nSourceTokens ≤ Threshold     → BackendGemini  (Sweep PP/DDD class)
//  4. (src, tgt) in HIGH_QUALITY    → BackendOpusMT  (sentence-context win)
//  5. Anything else                 → BackendGemini  (Sweep PP class)
//
// Pure function. No I/O. Mirrors the Python `select_translator`.
//
// Caller normalizes locales before calling; this function does not
// normalize. kielo-shared/locale.NormalizeLocaleCode is the canonical
// normalizer in this monorepo.
func SelectTranslator(src, tgt string, nSourceTokens int) Backend {
	if src == "" || tgt == "" {
		return BackendPassthrough
	}
	if src == tgt {
		return BackendPassthrough
	}
	if nSourceTokens <= ShortInputTokenThreshold {
		return BackendGemini
	}
	if _, ok := opusMTHighQualityPairs[[2]string{src, tgt}]; ok {
		return BackendOpusMT
	}
	return BackendGemini
}

// SelectTranslatorBatch is the convenience wrapper that does the
// MIN-tokens-over-batch calculation before dispatching to
// SelectTranslator. Returns BackendPassthrough for empty input.
//
// Caller's typical pattern:
//
//	backend := translation.SelectTranslatorBatch(src, tgt, texts)
//	switch backend {
//	case translation.BackendOpusMT: ...
//	case translation.BackendGemini: ...
//	case translation.BackendPassthrough: return texts // unchanged
//	}
func SelectTranslatorBatch(src, tgt string, texts []string) Backend {
	src = strings.TrimSpace(src)
	tgt = strings.TrimSpace(tgt)
	if len(texts) == 0 {
		return BackendPassthrough
	}
	return SelectTranslator(src, tgt, NSourceTokensMin(texts))
}
