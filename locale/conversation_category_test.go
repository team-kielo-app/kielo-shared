package locale

import "testing"

func TestConversationCategoryLabel_EnglishCanonical(t *testing.T) {
	if got := ConversationCategoryLabel("food-dining", "en"); got != "Food & dining" {
		t.Fatalf("food-dining en: got %q", got)
	}
	if got := ConversationCategoryLabel("food-dining", ""); got != "Food & dining" {
		t.Fatalf("food-dining default: got %q", got)
	}
}

func TestConversationCategoryLabel_VietnameseHappyPath(t *testing.T) {
	if got := ConversationCategoryLabel("food-dining", "vi"); got != "Ẩm thực & ăn uống" {
		t.Fatalf("food-dining vi: got %q", got)
	}
	if got := ConversationCategoryLabel("everyday-life", "vi-VN"); got != "Đời sống hàng ngày" {
		t.Fatalf("region-coded vi-VN: got %q", got)
	}
}

func TestConversationCategoryLabel_UnknownLocaleFallsBackToEnglish(t *testing.T) {
	if got := ConversationCategoryLabel("food-dining", "de"); got != "Food & dining" {
		t.Fatalf("unknown locale: got %q", got)
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
	cases := []struct {
		key, loc, want string
	}{
		{"main", "en", "Main"},
		{"other", "en", "Other"},
		{"main", "vi", "Chính"},
		{"other", "vi", "Khác"},
		{"main", "", "Main"},
		{"unknown", "vi", "unknown"},
	}
	for _, tc := range cases {
		if got := ConversationBucketLabel(tc.key, tc.loc); got != tc.want {
			t.Fatalf("(%q,%q): got %q want %q", tc.key, tc.loc, got, tc.want)
		}
	}
}
