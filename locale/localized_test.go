package locale

import "testing"

func TestPickLocalizedString_PrefersRequestedLocale(t *testing.T) {
	values := map[string]string{
		"en": "Order a coffee",
		"vi": "Gọi một ly cà phê",
		"sv": "Beställ en kaffe",
	}
	if got := PickLocalizedString(values, "vi", "fallback"); got != "Gọi một ly cà phê" {
		t.Fatalf("vi pick: got %q", got)
	}
	if got := PickLocalizedString(values, "sv", "fallback"); got != "Beställ en kaffe" {
		t.Fatalf("sv pick: got %q", got)
	}
}

func TestPickLocalizedString_FallsBackToEnglish(t *testing.T) {
	values := map[string]string{
		"en": "Order a coffee",
		"sv": "Beställ en kaffe",
	}
	if got := PickLocalizedString(values, "vi", "fallback"); got != "Order a coffee" {
		t.Fatalf("vi missing → en fallback: got %q", got)
	}
}

func TestPickLocalizedString_FallsBackToSuppliedDefault(t *testing.T) {
	values := map[string]string{"sv": "Beställ en kaffe"}
	if got := PickLocalizedString(values, "vi", "Tilaa kahvia"); got != "Tilaa kahvia" {
		t.Fatalf("vi missing + en missing → fallback: got %q", got)
	}
}

func TestPickLocalizedString_TreatsBlankValuesAsMissing(t *testing.T) {
	values := map[string]string{
		"vi": "   ",
		"en": "Order a burger",
	}
	if got := PickLocalizedString(values, "vi", "fallback"); got != "Order a burger" {
		t.Fatalf("blank vi → en: got %q", got)
	}
}

func TestPickLocalizedString_EmptyRequestedReturnsFallback(t *testing.T) {
	values := map[string]string{"en": "Order a burger"}
	if got := PickLocalizedString(values, "", "raw"); got != "raw" {
		t.Fatalf("empty requested → fallback: got %q", got)
	}
}

func TestPickLocalizedString_NilMapReturnsFallback(t *testing.T) {
	if got := PickLocalizedString(nil, "vi", "raw"); got != "raw" {
		t.Fatalf("nil map → fallback: got %q", got)
	}
}

func TestPickLocalizedStringJSON_DecodesAndResolves(t *testing.T) {
	raw := []byte(`{"vi":"Gọi món hamburger","en":"Order a burger"}`)
	if got := PickLocalizedStringJSON(raw, "vi", "fallback"); got != "Gọi món hamburger" {
		t.Fatalf("jsonb vi pick: got %q", got)
	}
	if got := PickLocalizedStringJSON(raw, "fr", "Hampurilainen"); got != "Order a burger" {
		t.Fatalf("jsonb fr missing → en: got %q", got)
	}
}

func TestPickLocalizedStringJSON_EmptyOrMalformed(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"nil bytes", nil},
		{"empty bytes", []byte{}},
		{"empty object", []byte(`{}`)},
		{"malformed", []byte(`{not-json`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PickLocalizedStringJSON(tc.raw, "vi", "fallback"); got != "fallback" {
				t.Fatalf("%s: got %q, want fallback", tc.name, got)
			}
		})
	}
}
