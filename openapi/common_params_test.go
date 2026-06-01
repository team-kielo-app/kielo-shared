package openapi

import "testing"

// TestCommonParamsCanonicalNames pins the canonical query-param names
// defined in ADR-006 §3.83 and the broader Request Handling Standard.
// Renaming any of these is a wire-contract change and must be done
// deliberately — this test exists to make accidental drift impossible.
//
// If you intentionally rename a canonical param, update this test AND
// every client (admin-ui, kielo-app, mobile) AND bump the OpenAPI
// version stamp; do NOT just silently retype the constant.
func TestCommonParamsCanonicalNames(t *testing.T) {
	cases := []struct {
		got  ParamSpec
		name string
		typ  string
		in   string
	}{
		{CommonParams.SupportLanguageCode(), "support_language_code", "string", "query"},
		{CommonParams.LearningLanguageCode(), "learning_language_code", "string", "query"},
		{CommonParams.PageSize(), "page_size", "integer", "query"},
		{CommonParams.NextPageKey(), "next_page_key", "string", "query"},
		{CommonParams.Cursor(), "cursor", "string", "query"},
		{CommonParams.Limit(), "limit", "integer", "query"},
		{CommonParams.Offset(), "offset", "integer", "query"},
		{CommonParams.Q(), "q", "string", "query"},
		{CommonParams.Search(), "search", "string", "query"},
		{CommonParams.Status(), "status", "string", "query"},
		{CommonParams.Category(), "category", "string", "query"},
		{CommonParams.SortBy(), "sort_by", "string", "query"},
		{CommonParams.Types(), "types", "string", "query"},
		{CommonParams.IDs(), "ids", "string", "query"},
		{CommonParams.Tag(), "tag", "string", "query"},
		{CommonParams.CEFRLevel(), "cefr_level", "string", "query"},
		{CommonParams.SkillLevel(), "skill_level", "string", "query"},
		{CommonParams.Bucket(), "bucket", "string", "query"},
		{CommonParams.ExcludeRead(), "exclude_read", "boolean", "query"},
		{CommonParams.IncludeEvents(), "include_events", "boolean", "query"},
		{CommonParams.ForceRefresh(), "force_refresh", "boolean", "query"},
		{CommonParams.Date(), "date", "string", "query"},
		{CommonParams.Count(), "count", "integer", "query"},
		{CommonParams.CountPerLevel(), "count_per_level", "integer", "query"},
		{CommonParams.ItemLimit(), "item_limit", "integer", "query"},
		{CommonParams.ExercisesPerItem(), "exercises_per_item", "integer", "query"},
		{CommonParams.SessionID(), "session_id", "string", "query"},
		{CommonParams.SessionIDCamel(), "sessionId", "string", "query"},
		{CommonParams.FlowID(), "flow_id", "string", "query"},
		{CommonParams.ScenarioID(), "scenarioId", "string", "query"},
		{CommonParams.ContextSentence(), "context_sentence", "string", "query"},
		{CommonParams.Word(), "word", "string", "query"},
		{CommonParams.ChallengeDateStr(), "challenge_date_str", "string", "query"},
		{CommonParams.Unread(), "unread", "boolean", "query"},
	}

	for _, c := range cases {
		if c.got.Name != c.name {
			t.Errorf("Name = %q, want %q", c.got.Name, c.name)
		}
		if c.got.Type != c.typ {
			t.Errorf("%s: Type = %q, want %q", c.name, c.got.Type, c.typ)
		}
		if c.got.In != c.in {
			t.Errorf("%s: In = %q, want %q", c.name, c.got.In, c.in)
		}
		if c.got.Description == "" {
			t.Errorf("%s: Description is empty", c.name)
		}
	}
}

// TestCommonParamsAllOptionalByDefault locks in that every canonical
// helper returns Required=false. Required-ness is a per-route decision;
// callers opt in via .AsRequired(). This prevents a future "let's just
// make support_language_code required" from breaking every route at
// once.
func TestCommonParamsAllOptionalByDefault(t *testing.T) {
	params := []ParamSpec{
		CommonParams.SupportLanguageCode(),
		CommonParams.LearningLanguageCode(),
		CommonParams.PageSize(),
		CommonParams.NextPageKey(),
		CommonParams.Cursor(),
		CommonParams.Limit(),
		CommonParams.Offset(),
		CommonParams.Q(),
		CommonParams.Search(),
		CommonParams.Status(),
		CommonParams.Category(),
		CommonParams.SortBy(),
		CommonParams.SessionID(),
		CommonParams.FlowID(),
		CommonParams.ScenarioID(),
	}
	for _, p := range params {
		if p.Required {
			t.Errorf("%q: Required = true, want false (use AsRequired() at the call site)", p.Name)
		}
	}
}

// TestParamSpecModifiers covers the .AsRequired / .AsOptional /
// .WithDescription helpers. These are tiny but central to the helper
// contract — every override at a call site flows through them.
func TestParamSpecModifiers(t *testing.T) {
	base := CommonParams.SupportLanguageCode()

	required := base.AsRequired()
	if !required.Required {
		t.Error("AsRequired() did not set Required=true")
	}
	if base.Required {
		t.Error("AsRequired() mutated the original (should return a copy)")
	}

	optional := required.AsOptional()
	if optional.Required {
		t.Error("AsOptional() did not set Required=false")
	}
	if !required.Required {
		t.Error("AsOptional() mutated the original (should return a copy)")
	}

	withDesc := base.WithDescription("custom override")
	if withDesc.Description != "custom override" {
		t.Errorf("WithDescription() = %q, want %q", withDesc.Description, "custom override")
	}
	if base.Description == "custom override" {
		t.Error("WithDescription() mutated the original (should return a copy)")
	}
}
