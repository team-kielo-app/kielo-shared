package locale

import "testing"

// Post-Round-10C contract:
//
// The conversationCategorySeed declares ONLY English entries — non-en
// locales come from localization.dynamic_translations via the
// dynamicregistry wrap (admin-curated) or from the Round 10D
// autotranslate-on-miss path (LLM-curated, status='machine').
//
// These tests pin the bare-seed contract (no dynamicregistry wrap,
// no admin overrides): English wins always; non-en locales fall back
// to English. Wrap behavior (vi/sv/ja/etc.) is tested at the
// consumer service level where dynamicregistry is actually wired.

func TestConversationCategoryLabel_EnglishCanonical(t *testing.T) {
	if got := ConversationCategoryLabel("food-dining", "en"); got != "Food & dining" {
		t.Fatalf("food-dining en: got %q", got)
	}
	if got := ConversationCategoryLabel("food-dining", ""); got != "Food & dining" {
		t.Fatalf("food-dining default: got %q", got)
	}
}

// Post-Round-10C: bare seed has only English. Vi label is admin-
// curated via localization.dynamic_translations and only surfaces
// when the dynamicregistry wrap is wired in main.go. The bare-seed
// path returns the English canonical as fallback.
func TestConversationCategoryLabel_NonEnglishFallsBackToEnglish(t *testing.T) {
	cases := []struct {
		key, loc string
	}{
		{"food-dining", "vi"},
		{"food-dining", "vi-VN"},
		{"everyday-life", "vi"},
		{"food-dining", "de"}, // unknown locale also falls back
		{"food-dining", "ja"},
		{"food-dining", "fi"},
	}
	for _, tc := range cases {
		// Get the canonical English for the key first.
		canonical := ConversationCategoryLabel(tc.key, "en")
		if got := ConversationCategoryLabel(tc.key, tc.loc); got != canonical {
			t.Fatalf("(%q,%q): got %q want canonical %q (English fallback per Round 10C contract)",
				tc.key, tc.loc, got, canonical)
		}
	}
}

func TestConversationCategoryLabel_UnknownKeyAutoTitleCases(t *testing.T) {
	if got := ConversationCategoryLabel("foo-bar", "vi"); got != "Foo Bar" {
		t.Fatalf("unknown key: got %q", got)
	}
	if got := ConversationCategoryLabel("foo_bar", "en"); got != "Foo Bar" {
		t.Fatalf("underscore key: got %q", got)
	}
}

func TestConversationCategoryLabel_EmptyKey(t *testing.T) {
	if got := ConversationCategoryLabel("", "vi"); got != "" {
		t.Fatalf("empty key: got %q", got)
	}
}

func TestConversationBucketLabel(t *testing.T) {
	// Post-Round-10C: bucket labels are English-only in the bare seed.
	// Non-en locales fall back to English; admin curates via the
	// dynamicregistry wrap when wired in consumer main.go.
	cases := []struct {
		key, loc, want string
	}{
		{"main", "en", "Main"},
		{"other", "en", "Other"},
		{"main", "vi", "Main"},   // post-Round-10C: en fallback
		{"other", "vi", "Other"}, // post-Round-10C: en fallback
		{"main", "", "Main"},
		{"main", "ja", "Main"}, // unknown locale also en fallback
		{"unknown", "vi", "unknown"},
	}
	for _, tc := range cases {
		if got := ConversationBucketLabel(tc.key, tc.loc); got != tc.want {
			t.Fatalf("(%q,%q): got %q want %q", tc.key, tc.loc, got, tc.want)
		}
	}
}
