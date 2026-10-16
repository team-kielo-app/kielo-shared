package locale

import (
	"strings"
	"testing"
)

func FuzzNormalizeLocaleCode(f *testing.F) {
	for _, seed := range []string{"fi", "FI", "en-US", "pt_BR", "zh-Hans", "ars", "vn", " fi ", "", "-", "_", "fin", "ar-SA", "İ", "\x00", "fi "} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := NormalizeLocaleCode(raw)
		if got != strings.ToLower(got) || strings.ContainsAny(got, "-_") {
			t.Fatalf("NormalizeLocaleCode(%q) = %q keeps a subtag separator or upper case", raw, got)
		}
		if again := NormalizeLocaleCode(got); again != got {
			t.Fatalf("NormalizeLocaleCode not idempotent: %q -> %q -> %q", raw, got, again)
		}
		if learning := NormalizeLearningLanguageCode(raw); learning != "" && (learning != got || !IsSupportedLearningLanguage(learning)) {
			t.Fatalf("NormalizeLearningLanguageCode(%q) = %q, base %q", raw, learning, got)
		}
		accept := NormalizeAcceptLanguage(raw)
		if accept != strings.ToLower(accept) || strings.ContainsAny(accept, "-_,;") {
			t.Fatalf("NormalizeAcceptLanguage(%q) = %q", raw, accept)
		}
		if IsSupportedSupportLanguage(raw) && !IsSupportedSupportLanguage(got) {
			t.Fatalf("supported %q normalizes to unsupported %q", raw, got)
		}
	})
}
