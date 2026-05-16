package supportregistry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapRegistry_ResolveExactMatch(t *testing.T) {
	r := New([]string{"en", "vi"})
	r.Set("morphology.word_class.teonsana", "en", "Verb")
	r.Set("morphology.word_class.teonsana", "vi", "động từ")

	assert.Equal(t, "Verb", r.Resolve(context.Background(), "morphology.word_class.teonsana", "en"))
	assert.Equal(t, "động từ", r.Resolve(context.Background(), "morphology.word_class.teonsana", "vi"))
}

func TestMapRegistry_FallsBackToEnglish(t *testing.T) {
	r := New([]string{"en", "vi", "ar"})
	r.Set("ui.greeting", "en", "Hello")
	r.Set("ui.greeting", "vi", "Xin chào")
	// "ar" intentionally not set — should fall back to English.

	assert.Equal(t, "Hello", r.Resolve(context.Background(), "ui.greeting", "ar"))
}

func TestMapRegistry_UnknownKeyReturnsKeyItself(t *testing.T) {
	r := New([]string{"en", "vi"})
	got := r.Resolve(context.Background(), "ui.does_not_exist", "vi")
	// Contract: never returns empty. Returning the key tells the
	// caller "I don't have this", but the UI can still render it.
	assert.Equal(t, "ui.does_not_exist", got)
}

func TestMapRegistry_NormalizesLocaleCase(t *testing.T) {
	r := New([]string{"en", "vi"})
	r.Set("ui.greeting", "vi", "Xin chào")
	// Caller passes "VI" or "Vi-VN" — registry should still find it.
	// (Real BCP-47 normalization happens at the LanguageResolver layer
	// before reaching the registry; we just lower-case + trim defensively.)
	assert.Equal(t, "Xin chào", r.Resolve(context.Background(), "ui.greeting", "VI"))
	assert.Equal(t, "Xin chào", r.Resolve(context.Background(), "ui.greeting", " vi "))
}

func TestMapRegistry_FinalizeBlocksWrites(t *testing.T) {
	r := New([]string{"en", "vi"})
	r.Set("ui.greeting", "en", "Hello")
	r.Finalize()

	ok := r.Set("ui.greeting", "vi", "Should not stick")
	assert.False(t, ok, "Set after Finalize must return false")

	// Existing entries still resolve; the late Set was a no-op.
	assert.Equal(t, "Hello", r.Resolve(context.Background(), "ui.greeting", "en"))
	// vi was never registered, so it falls back to English.
	assert.Equal(t, "Hello", r.Resolve(context.Background(), "ui.greeting", "vi"))
}

func TestMapRegistry_AlwaysIncludesEnglishInSupportedLocales(t *testing.T) {
	// Even if caller forgets en, the registry adds it. English is the
	// universal fallback per the FallbackLocale contract.
	r := New([]string{"fi", "vi"})
	got := r.SupportedLocales()
	assert.Contains(t, got, "en")
	assert.Contains(t, got, "fi")
	assert.Contains(t, got, "vi")
}

func TestMapRegistry_TemplateSubstitution(t *testing.T) {
	r := New([]string{"en", "vi"})
	r.Set("ui.welcome", "en", "Hello, {{.Name}}!")
	r.Set("ui.welcome", "vi", "Xin chào, {{.Name}}!")

	out := r.ResolveTemplate(context.Background(), "ui.welcome", "vi", map[string]any{"Name": "Khanh"})
	assert.Equal(t, "Xin chào, Khanh!", out)
}

func TestMapRegistry_TemplateMissingKeyDoesNotPanic(t *testing.T) {
	r := New([]string{"en"})
	r.Set("ui.welcome", "en", "Hello, {{.Name}}!")

	// Contract: missing template keys must not panic. The exact
	// substitution string depends on Go's text/template default
	// (`<no value>` when params is nil; "" when params is a typed map
	// with `missingkey=zero`). What matters is non-crash and a
	// recognisable output, not the exact bytes.
	out := r.ResolveTemplate(context.Background(), "ui.welcome", "en", nil)
	assert.Contains(t, out, "Hello,")
}

func TestMapRegistry_TemplateMissingKeyDoesNotCrashWithEmptyMap(t *testing.T) {
	r := New([]string{"en"})
	r.Set("ui.welcome", "en", "Hello, {{.Name}}!")

	// With a non-nil but empty params map, text/template prints
	// "<no value>" for missing keys (the `missingkey=zero` option
	// only applies to map LOOKUPS, not field accesses; `.Name` is
	// a field access here). Contract is just: no panic.
	out := r.ResolveTemplate(context.Background(), "ui.welcome", "en", map[string]any{})
	assert.Contains(t, out, "Hello,")
}

func TestMapRegistry_TemplateParseFailureFallsThroughToLiteral(t *testing.T) {
	r := New([]string{"en"})
	r.Set("ui.broken", "en", "Hello, {{.Name") // missing closing braces

	out := r.ResolveTemplate(context.Background(), "ui.broken", "en", map[string]any{"Name": "x"})
	// Contract: malformed template returns literal rather than crashing.
	// Surfacing raw template syntax to the user is still better than 500.
	assert.Equal(t, "Hello, {{.Name", out)
}

func TestMapRegistry_NoTemplateSyntaxSkipsTemplating(t *testing.T) {
	r := New([]string{"en"})
	r.Set("ui.plain", "en", "Plain text no substitution")

	// Fast path for strings without {{ — should not even attempt template.Parse.
	out := r.ResolveTemplate(context.Background(), "ui.plain", "en", map[string]any{"Name": "ignored"})
	assert.Equal(t, "Plain text no substitution", out)
}

func TestMapRegistry_CoverageReport(t *testing.T) {
	r := New([]string{"en", "vi", "ar"})
	r.Set("ui.k1", "en", "K1")
	r.Set("ui.k1", "vi", "K1-vi")
	r.Set("ui.k2", "en", "K2")
	// ui.k1 has en + vi.  ui.k2 only has en.

	report := r.CoverageReport()
	assert.Equal(t, 2, report["en"].Total)
	assert.Equal(t, 2, report["en"].Localized) // every key has en
	assert.Equal(t, 1, report["vi"].Localized) // only k1 has vi
	assert.Equal(t, 1, report["vi"].Fallback)  // k2 falls back
	assert.Equal(t, 0, report["ar"].Localized) // no ar entries
	assert.Equal(t, 2, report["ar"].Fallback)  // both fall back
}

func TestMapRegistry_ResolveSafeWithoutRegistration(t *testing.T) {
	r := New([]string{"en", "vi"})
	// Don't register anything. Resolve must still be safe.
	got := r.Resolve(context.Background(), "ui.anything", "vi")
	assert.Equal(t, "ui.anything", got)
}
