// Arc G1 (2026-06-08): typed-vocabulary SoT for `InAppNudgeContext`
// — the canonical CURRENT-SCREEN-CATEGORY enum used by Loop G per
// `docs/architecture/learning-architecture-reform.md` §6.7.
//
// Mobile maps `current_route` → `InAppNudgeContext` at call time;
// server only sees the canonical context label. The endpoint
// `GET /api/v3/me/in-app-nudges?context=<canonical>` returns at most
// ONE nudge per context.
//
// **Why semantic context (not 1:1 route-tree mapping)**: per recon 3:
//   - Aligns with ADR-011 spine event_type prefixes (article.*,
//     conversation.*, video.* etc.) — the closed vocab existing
//     producers already pattern-match against.
//   - Aligns with `users.feature_usage` feature names (`time_spent:
//     reading`, `convo_seconds_daily` etc.) — the existing per-day
//     engagement primitive `LearnerObservationService` consumes.
//   - Stable across mobile route refactors — the contract is "what is
//     the user doing right now," not "where in the UI tree."
//   - Cardinality stays bounded (8 contexts vs ~25+ stable screens).
//
// 18th typed-vocab SoT module in kielo-shared/vocab/ (after
// inappnudgetype + 16 prior instances).
//
// Cross-language Python mirror at
// `kielo-shared/kielo_shared/vocab/in_app_nudge_context.py`.
// V117 migration applies CHECK constraint pinning this enum on
// `users.in_app_nudge_state.context`. Contract test at
// `tests/contract/in_app_nudge_context_vocabulary_contract_test.go`
// pins the 3-anchor invariant (SoT non-empty + Go↔Python parity +
// V117-CHECK parity).
//
// **Cardinality discipline rule**: every new InAppNudgeContext value
// MUST (a) map to at least one ADR-011 event_type prefix OR
// `feature_usage` feature name, (b) ship Python mirror + V117a
// migration + contract test in lockstep. Hard cap 10 contexts for v1.
package vocab

// InAppNudgeContext is the canonical CURRENT-USER-ACTIVITY enum
// driving Loop G nudge selection.
//
// 8 values split into 3 "idle" tab contexts (user is between
// activities — best moment to surface a next-loop hint) + 5 "session"
// contexts (user is mid-content — only specific high-urgency nudges
// fire here).
type InAppNudgeContext string

// String returns the wire string for query-param + SQL CHECK
// compatibility.
func (c InAppNudgeContext) String() string { return string(c) }

// Canonical InAppNudgeContext vocabulary (8 values, hard-cap 10).
//
// Mapping to mobile route segments + ADR-011 event_type prefixes:
const (
	// --- 3 "idle" tab contexts (user between activities) ---

	// InAppNudgeContextHomeIdle — `/(main)/(tabs)/index`
	// (post-Arc-1A this tab is deprioritized; users primarily land
	// here via last-used-feature router on cold-boot). Best moment to
	// surface "you have N reviews waiting" or "try a scenario."
	InAppNudgeContextHomeIdle InAppNudgeContext = "home_idle"

	// InAppNudgeContextRoadmapIdle — `/(main)/(tabs)/roadmap`
	// (the exercises tab in code; routes via ROADMAP_TAB_PATH). User
	// is browsing curriculum. Best moment for completionist nudges +
	// scenario-first-time prompts (they're already in learning mode).
	InAppNudgeContextRoadmapIdle InAppNudgeContext = "roadmap_idle"

	// InAppNudgeContextProfileIdle — `/(main)/(tabs)/profile` or
	// `/(main)/settings/*`. User is in account-management mode. Limited
	// nudge surface (don't interrupt settings flows).
	InAppNudgeContextProfileIdle InAppNudgeContext = "profile_idle"

	// --- 5 "session" contexts (user mid-content) ---
	// Each maps to one ADR-011 event_type prefix + one feature_usage
	// feature, so eligibility predicates compose against existing
	// signal.

	// InAppNudgeContextReadingSession — article reader screen
	// (`/(main)/reader/[id]`). Maps to ADR-011 `article.*` prefix +
	// `time_spent:reading` feature. Cross-feature nudges fire here for
	// review_backlog (Loop B re-entry mid-Loop-A).
	InAppNudgeContextReadingSession InAppNudgeContext = "reading_session"

	// InAppNudgeContextVideoSession — KTV/tv player screens. Maps to
	// ADR-011 `video.*` prefix + `kielotv_watch_seconds` feature. Same
	// cross-feature nudge eligibility as reading_session.
	InAppNudgeContextVideoSession InAppNudgeContext = "video_session"

	// InAppNudgeContextConversationSession — conversation-intro /
	// conversation-session / conversation-transcript screens. Maps to
	// ADR-011 `conversation.*` prefix + `convo_seconds_daily` feature.
	// Cross-feature nudges fire here for convo_user_try_reading (Loop F
	// transfer to articles).
	InAppNudgeContextConversationSession InAppNudgeContext = "conversation_session"

	// InAppNudgeContextExerciseSession — daily challenge / lesson
	// player / custom deck. Maps to ADR-011 `exercise.*` + `lesson.*`
	// prefixes. Loop B in-progress; cross-feature nudges generally
	// suppressed here (user is already in retrieval mode).
	InAppNudgeContextExerciseSession InAppNudgeContext = "exercise_session"

	// InAppNudgeContextDiscoveryBrowse — saved-items, learning-items
	// list, concept-hub list, search, news category browse. User is
	// exploring without committing to a single piece of content.
	// Generally permissive nudge surface.
	InAppNudgeContextDiscoveryBrowse InAppNudgeContext = "discovery_browse"
)

// AllInAppNudgeContexts is the canonical iteration order, grouped by
// idle/session semantic.
var AllInAppNudgeContexts = []InAppNudgeContext{
	// Idle contexts (3)
	InAppNudgeContextHomeIdle,
	InAppNudgeContextRoadmapIdle,
	InAppNudgeContextProfileIdle,
	// Session contexts (5)
	InAppNudgeContextReadingSession,
	InAppNudgeContextVideoSession,
	InAppNudgeContextConversationSession,
	InAppNudgeContextExerciseSession,
	InAppNudgeContextDiscoveryBrowse,
}

// IsValidInAppNudgeContext reports whether the given value is a known
// canonical context. Mobile MUST call this at request-time before
// emitting the value as a query param; server MUST call this at API
// boundary before consuming.
func IsValidInAppNudgeContext(c InAppNudgeContext) bool {
	switch c {
	case InAppNudgeContextHomeIdle,
		InAppNudgeContextRoadmapIdle,
		InAppNudgeContextProfileIdle,
		InAppNudgeContextReadingSession,
		InAppNudgeContextVideoSession,
		InAppNudgeContextConversationSession,
		InAppNudgeContextExerciseSession,
		InAppNudgeContextDiscoveryBrowse:
		return true
	}
	return false
}
