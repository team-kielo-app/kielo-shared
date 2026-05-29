// Package openapi: canonical reusable ParamSpec builders.
//
// These helpers centralize the canonical query-parameter names defined in
// ADR-006 (Request Handling Standard) so per-route registrations stay
// terse and consistent across services. Hand-writing `ParamSpec{Name:
// "support_language_code", In: "query", Type: "string"}` at every
// registration site invited drift (`locale`, `lang`, `language_code` all
// appeared at various points); these builders give one source of truth.
//
// Usage pattern:
//
//	v3.GET("/news/articles", h.ListArticles, openapi.Route{
//	    Tag: "articles",
//	    QueryParams: []openapi.ParamSpec{
//	        openapi.CommonParams.SupportLanguageCode(),
//	        openapi.CommonParams.WithTranslation(),
//	        openapi.CommonParams.PageSize(),
//	        openapi.CommonParams.NextPageKey(),
//	    },
//	    Response: pagination.CursorPage[models.Article]{},
//	})
//
// All helpers return a value (not a pointer) so callers can append the
// result directly to a `[]ParamSpec` literal. Required-ness defaults
// match the documented contract; pass through `.AsRequired()` when a
// route inverts the default.
package openapi

// commonParams is the singleton handle exposed as `openapi.CommonParams`.
// It's a zero-size struct so the helpers read like a namespace at call
// sites without paying any runtime cost.
type commonParams struct{}

// CommonParams is the canonical entry point for reusable query-parameter
// builders. See package doc for usage.
var CommonParams = commonParams{}

// AsRequired returns a copy of p with Required=true. Use when a route
// inverts a default-optional canonical param.
func (p ParamSpec) AsRequired() ParamSpec {
	p.Required = true
	return p
}

// AsOptional returns a copy of p with Required=false. Use when a route
// inverts a default-required canonical param.
func (p ParamSpec) AsOptional() ParamSpec {
	p.Required = false
	return p
}

// WithDescription returns a copy of p with a route-specific description.
// The defaults are generic; tighten them when the param has special
// semantics for one route (e.g. cursor on a non-paginated feed).
func (p ParamSpec) WithDescription(desc string) ParamSpec {
	p.Description = desc
	return p
}

// ---------------------------------------------------------------------------
// Language / locale params (ADR-006 §3.83)
// ---------------------------------------------------------------------------

// SupportLanguageCode is the canonical "translate UI/strings into this
// language" query param. Two-letter ISO 639-1. Optional — resolution
// order: explicit query/header → user profile → Accept-Language →
// learning-lang fallback → "en".
func (commonParams) SupportLanguageCode() ParamSpec {
	return ParamSpec{
		Name:        "support_language_code",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Two-letter ISO 639-1 code for translated UI strings (per ADR-006 §3.83).",
	}
}

// LearningLanguageCode is the canonical "content is being learned in
// this language" query param. Two-letter ISO 639-1. Optional —
// resolution order: explicit query → X-Kielo-Learning-Language →
// X-Learning-Language (legacy) → JWT claim → 422.
func (commonParams) LearningLanguageCode() ParamSpec {
	return ParamSpec{
		Name:        "learning_language_code",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Two-letter ISO 639-1 code for the language being learned (per ADR-006 §3.83).",
	}
}

// WithTranslation toggles translated paragraphs/strings in the response
// payload. Defaults to false at the handler level; declare explicitly so
// the spec advertises the toggle to clients.
func (commonParams) WithTranslation() ParamSpec {
	return ParamSpec{
		Name:        "with_translation",
		In:          "query",
		Type:        "boolean",
		Required:    false,
		Description: "When true, response includes translated paragraphs/strings in support_language_code.",
	}
}

// ---------------------------------------------------------------------------
// Cursor-based pagination params (canonical per ADR-006)
// ---------------------------------------------------------------------------

// PageSize is the canonical page-size param for cursor-paginated lists.
// Integer, optional, handler-side default. Use AsRequired() if a route
// truly requires it (rare).
func (commonParams) PageSize() ParamSpec {
	return ParamSpec{
		Name:        "page_size",
		In:          "query",
		Type:        "integer",
		Required:    false,
		Description: "Maximum number of items per page. Handler default applies if omitted.",
	}
}

// NextPageKey is the canonical pagination cursor for cursor-paginated
// lists. Opaque string returned by previous response's CursorPage
// envelope.
func (commonParams) NextPageKey() ParamSpec {
	return ParamSpec{
		Name:        "next_page_key",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Opaque pagination cursor returned by the previous response.",
	}
}

// Cursor is an alias for routes that still expose `cursor` (legacy name
// kept where it predates the standard). Prefer NextPageKey on new
// routes; this exists so the spec accurately reflects routes that
// haven't migrated yet.
func (commonParams) Cursor() ParamSpec {
	return ParamSpec{
		Name:        "cursor",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Opaque pagination cursor (legacy alias for next_page_key).",
	}
}

// ---------------------------------------------------------------------------
// Offset-based pagination (legacy / non-cursor routes)
// ---------------------------------------------------------------------------

// Limit is the offset-pagination companion to Offset. Prefer PageSize
// on new routes; use Limit/Offset only where the upstream service still
// speaks offset pagination.
func (commonParams) Limit() ParamSpec {
	return ParamSpec{
		Name:        "limit",
		In:          "query",
		Type:        "integer",
		Required:    false,
		Description: "Legacy offset-pagination limit. Prefer page_size on new routes.",
	}
}

// Offset is the offset-pagination companion to Limit.
func (commonParams) Offset() ParamSpec {
	return ParamSpec{
		Name:        "offset",
		In:          "query",
		Type:        "integer",
		Required:    false,
		Description: "Legacy offset-pagination offset. Prefer next_page_key on new routes.",
	}
}

// ---------------------------------------------------------------------------
// Filter / sort params
// ---------------------------------------------------------------------------

// Q is the canonical free-text search param.
func (commonParams) Q() ParamSpec {
	return ParamSpec{
		Name:        "q",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Free-text search query.",
	}
}

// Search is an alias for routes that expose `search` instead of `q`
// (e.g. feedback features). Prefer Q on new routes.
func (commonParams) Search() ParamSpec {
	return ParamSpec{
		Name:        "search",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Free-text search query.",
	}
}

// Status filters list responses by a status enum.
func (commonParams) Status() ParamSpec {
	return ParamSpec{
		Name:        "status",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Filter results by status.",
	}
}

// Category filters list responses by a category enum.
func (commonParams) Category() ParamSpec {
	return ParamSpec{
		Name:        "category",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Filter results by category.",
	}
}

// SortBy controls list ordering. Value semantics are per-route.
func (commonParams) SortBy() ParamSpec {
	return ParamSpec{
		Name:        "sort_by",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Sort order for results (semantics per route).",
	}
}

// Types is a comma-separated list filter (e.g. feed item types).
func (commonParams) Types() ParamSpec {
	return ParamSpec{
		Name:        "types",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Comma-separated list of types to include.",
	}
}

// IDs is a comma-separated list of IDs to fetch / filter.
func (commonParams) IDs() ParamSpec {
	return ParamSpec{
		Name:        "ids",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Comma-separated list of IDs to fetch.",
	}
}

// Tag filters list responses by tag.
func (commonParams) Tag() ParamSpec {
	return ParamSpec{
		Name:        "tag",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Filter results by tag.",
	}
}

// CEFRLevel filters by CEFR proficiency level (A1, A2, B1, B2, C1, C2).
func (commonParams) CEFRLevel() ParamSpec {
	return ParamSpec{
		Name:        "cefr_level",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Filter by CEFR proficiency level (A1, A2, B1, B2, C1, C2).",
	}
}

// SkillLevel filters by per-user skill level.
func (commonParams) SkillLevel() ParamSpec {
	return ParamSpec{
		Name:        "skill_level",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Filter by skill level.",
	}
}

// Bucket is a generic bucket / segment selector used by recommendation
// routes.
func (commonParams) Bucket() ParamSpec {
	return ParamSpec{
		Name:        "bucket",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Selector for a named bucket / segment.",
	}
}

// ExcludeRead is a boolean toggle on feed-like routes.
func (commonParams) ExcludeRead() ParamSpec {
	return ParamSpec{
		Name:        "exclude_read",
		In:          "query",
		Type:        "boolean",
		Required:    false,
		Description: "When true, exclude items the user has already read.",
	}
}

// IncludeEvents toggles event records in list responses.
func (commonParams) IncludeEvents() ParamSpec {
	return ParamSpec{
		Name:        "include_events",
		In:          "query",
		Type:        "boolean",
		Required:    false,
		Description: "When true, include event records in the response.",
	}
}

// ForceRefresh bypasses caches for the request.
func (commonParams) ForceRefresh() ParamSpec {
	return ParamSpec{
		Name:        "force_refresh",
		In:          "query",
		Type:        "boolean",
		Required:    false,
		Description: "When true, bypass caches and refetch upstream.",
	}
}

// Date is an ISO-8601 date filter (YYYY-MM-DD).
func (commonParams) Date() ParamSpec {
	return ParamSpec{
		Name:        "date",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "ISO-8601 date filter (YYYY-MM-DD).",
	}
}

// ---------------------------------------------------------------------------
// Recommendation / discovery params
// ---------------------------------------------------------------------------

// Count is a generic count selector (small int, route-specific cap).
func (commonParams) Count() ParamSpec {
	return ParamSpec{
		Name:        "count",
		In:          "query",
		Type:        "integer",
		Required:    false,
		Description: "Number of items to return (route-specific cap).",
	}
}

// CountPerLevel applies to multi-level recommendation endpoints.
func (commonParams) CountPerLevel() ParamSpec {
	return ParamSpec{
		Name:        "count_per_level",
		In:          "query",
		Type:        "integer",
		Required:    false,
		Description: "Number of items per level for stratified recommendations.",
	}
}

// ItemLimit caps the items in a recommendation/discovery batch.
func (commonParams) ItemLimit() ParamSpec {
	return ParamSpec{
		Name:        "item_limit",
		In:          "query",
		Type:        "integer",
		Required:    false,
		Description: "Maximum number of items in a recommendation batch.",
	}
}

// ExercisesPerItem caps generated exercises per recommendation item.
func (commonParams) ExercisesPerItem() ParamSpec {
	return ParamSpec{
		Name:        "exercises_per_item",
		In:          "query",
		Type:        "integer",
		Required:    false,
		Description: "Maximum number of exercises generated per recommendation item.",
	}
}

// ---------------------------------------------------------------------------
// Session / flow / conversation params
// ---------------------------------------------------------------------------

// SessionID identifies a session (snake_case canonical).
func (commonParams) SessionID() ParamSpec {
	return ParamSpec{
		Name:        "session_id",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Identifier of the session this request belongs to.",
	}
}

// SessionIDCamel is the camelCase alias kept where the upstream
// provider speaks camelCase (rare in v3; prefer SessionID).
func (commonParams) SessionIDCamel() ParamSpec {
	return ParamSpec{
		Name:        "sessionId",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Identifier of the session (camelCase alias for session_id).",
	}
}

// FlowID identifies a flow execution.
func (commonParams) FlowID() ParamSpec {
	return ParamSpec{
		Name:        "flow_id",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Identifier of the flow execution.",
	}
}

// ScenarioID identifies a conversation scenario template (camelCase
// preserved where the upstream conversations service uses it).
func (commonParams) ScenarioID() ParamSpec {
	return ParamSpec{
		Name:        "scenarioId",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Identifier of the conversation scenario template.",
	}
}

// ContextSentence carries a contextual sentence for dictionary /
// translation lookups.
func (commonParams) ContextSentence() ParamSpec {
	return ParamSpec{
		Name:        "context_sentence",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Contextual sentence to disambiguate dictionary / translation lookups.",
	}
}

// Word is a dictionary lookup word.
func (commonParams) Word() ParamSpec {
	return ParamSpec{
		Name:        "word",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Word to look up in the dictionary.",
	}
}

// ChallengeDateStr identifies a daily challenge by date string.
func (commonParams) ChallengeDateStr() ParamSpec {
	return ParamSpec{
		Name:        "challenge_date_str",
		In:          "query",
		Type:        "string",
		Required:    false,
		Description: "Daily-challenge identifier as a date string (YYYY-MM-DD).",
	}
}

// Unread filters notifications to unread only (legacy alias kept on
// /me/notifications for backward compatibility).
func (commonParams) Unread() ParamSpec {
	return ParamSpec{
		Name:        "unread",
		In:          "query",
		Type:        "boolean",
		Required:    false,
		Description: "When true, return only unread notifications (legacy alias).",
	}
}
