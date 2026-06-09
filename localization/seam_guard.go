package localization

// SuspiciousTranslationGuard is the seam's quality gate for fresh
// provider output. Round 10D (sibling of Round 10A Python).
//
// Mirrors the canonical Sweep PP/QQ/KKK guard at
// kielolearn-engine ContentLocalizer._is_suspicious_translation
// (Layer 2 in Sweep QQ Pattern B). Pre-Round-10D the Python guard ran
// only at _via_registry / _via_registry_batch and the Go seam had no
// guard hook at all — any future autotranslate-callback path shipping
// junk into dynamic_translations would have silently landed.
//
// Guard implementations decide per (source, candidate, target) tuple
// whether the candidate is acceptable. Rule names mirror Sweep PP / QQ
// / KKK:
//
//   - 1  identity              candidate == source for non-trivial src
//   - 2  foreign-text-injection candidate contains non-Latin glyphs the
//        target locale doesn't use, OR contains source-language tokens
//        verbatim mid-sentence (en in vi output, etc.)
//   - 3  repeated-token loop   any 3-token n-gram repeats ≥ N times
//   - 3a short-output frequency single-token candidates with high
//        document frequency in the rejected output pool
//   - 3b consecutive-run       3+ identical consecutive tokens
//   - 4  truncation            candidate shorter than source by > 50%
//        for non-CJK targets
//   - 5  single-source-token degeneracy 1-token source → multi-word
//        candidate that's a hallucination pattern
//   - 5b premature 1-char      candidate is a single character for a
//        non-CJK target with multi-char source
//   - 6  glyph-replacement     candidate contains placeholders (?, □)
//   - 7  negation-injection    target=en/fi/sv/vi negation marker
//        absent from source candidate
//
// Returns true when the candidate IS suspicious (callers fall back to
// source). False means accept.
//
// Implementations MUST be safe for concurrent calls. The seam invokes
// the guard from goroutines (single-flight provider call returns share
// the guard verdict).
//
// Production wires CanonicalGuard (the Go port of Sweep PP/QQ/KKK 5
// canonical rules). Tests use NoopGuard for accept-all OR
// AlwaysSuspiciousGuard for reject-all path coverage.
type SuspiciousTranslationGuard interface {
	IsSuspicious(sourceText, candidate, targetLocale string) bool
}

// NoopGuard is a SuspiciousTranslationGuard that accepts everything.
// Use in tests + envs where the guard's domain knowledge isn't
// applicable.
//
// Pre-Round-10D this is the de-facto seam behaviour — every provider
// output was accepted unconditionally. Round 10D makes that explicit
// and pluggable.
type NoopGuard struct{}

// IsSuspicious implements SuspiciousTranslationGuard.
func (NoopGuard) IsSuspicious(_, _, _ string) bool { return false }

// AlwaysSuspiciousGuard is a test guard that rejects every candidate.
// Lets tests assert the fall-back-to-source path fires when the guard
// fires.
type AlwaysSuspiciousGuard struct{}

// IsSuspicious implements SuspiciousTranslationGuard.
func (AlwaysSuspiciousGuard) IsSuspicious(_, _, _ string) bool { return true }
