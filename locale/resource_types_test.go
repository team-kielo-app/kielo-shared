package locale

import (
	"sort"
	"testing"
)

func TestIsValidResourceType(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{ResourceTypeArticleTitle, true},
		{ResourceTypeScenarioDescription, true},
		{ResourceTypeEngineExerciseInstruction, true},
		{"article.unknown_field", false},
		{"", false},
		{"Article.Title", false}, // case-sensitive
	}
	for _, c := range cases {
		if got := IsValidResourceType(c.in); got != c.want {
			t.Errorf("IsValidResourceType(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAllResourceTypesContainsKnown(t *testing.T) {
	all := AllResourceTypes()
	sort.Strings(all)
	if len(all) < 15 {
		t.Fatalf("expected at least 15 resource types, got %d: %v", len(all), all)
	}
	// Spot-check a few — full list should match the consts block.
	required := []string{
		ResourceTypeArticleTitle,
		ResourceTypeArticleParagraph,
		ResourceTypeScenarioTitle,
		ResourceTypeKtvCaptionCue,
		ResourceTypeNotificationsBody,
	}
	for _, want := range required {
		found := false
		for _, got := range all {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AllResourceTypes() missing %q", want)
		}
	}
}

func TestResourceTypeNamingConvention(t *testing.T) {
	for _, rt := range AllResourceTypes() {
		if rt == "" {
			t.Errorf("empty resource type registered")
			continue
		}
		// Convention: lowercase, dot-separated, no leading/trailing dot.
		for _, r := range rt {
			if r >= 'A' && r <= 'Z' {
				t.Errorf("resource type %q contains uppercase character %q", rt, r)
				break
			}
		}
		if rt[0] == '.' || rt[len(rt)-1] == '.' {
			t.Errorf("resource type %q has leading or trailing dot", rt)
		}
	}
}
