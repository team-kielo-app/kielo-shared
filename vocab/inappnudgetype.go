// Arc G1 (2026-06-08): typed-vocabulary SoT for `InAppNudgeType`
// — the canonical category enum for Loop G (discovery / cross-feature
// promotion) per
// `docs/architecture/learning-architecture-reform.md` §6.7.
//
// Loop G fires when a learner is IN the app but on a feature OTHER than
// the higher-leverage next step. Distinct from R1-R5 push notifications
// (which fire when the learner is AWAY). Examples: roadmap-engaged
// learner who's never opened scenarios; scenario-engaged learner with
// 0 article reads; learner with ≥15 due reviews on a non-review surface.
//
// Initial v1 vocabulary derived empirically from a 10-user recon
// (52.7% population coverage in the 30-80% target band):
//
//	try_scenarios_first_time      — Loop C entry; 13.5% of active users
//	review_backlog_idle           — Loop B re-entry; 37.8% (largest)
//	roadmap_completionist_explore — Loop A/C entry post-Loop-E; 16.2%
//	convo_user_try_reading        — Loop F transfer entry; 8.1%
//
// 17th typed-vocab SoT module in kielo-shared/vocab/ (after
// useritemstatus + content_bridge + scenarioSourceType + emailSubjectKey
// + pushKey + itemtype + achievement + 10 prior instances).
//
// Cross-language Python mirror at
// `kielo-shared/kielo_shared/vocab/in_app_nudge_type.py`.
// V117 migration applies CHECK constraint pinning this enum on
// `users.in_app_nudge_state.nudge_type`. Contract test at
// `tests/contract/in_app_nudge_type_vocabulary_contract_test.go` pins
// the 3-anchor invariant (SoT non-empty + Go↔Python parity +
// V117-CHECK parity — Sweep ZK-B novel deploy-time SoT anchor for
// runtime-produced vocabularies).
//
// **Cardinality discipline rule**: adding a new InAppNudgeType MUST
// land in lockstep with (a) Python mirror constant, (b) V117a sibling
// migration extending the CHECK constraint, (c) NotificationRule-style
// copy rows for all 4 base locales (en/fi/sv/vi), (d) eligibility
// predicate in the corresponding engine `InAppNudgeAuthor`. Hard cap
// 12 nudge types for v1; expansion past 12 triggers cardinality recon.
package vocab

// InAppNudgeType is the canonical category enum for in-app
// cross-feature promotion nudges.
//
// Wire shape: lowercase snake_case for consistency with the R-series
// notification event_type vocabulary (`learning.review_due.v1` etc.)
// modulo the .v1 suffix (in-app nudges aren't envelope-versioned —
// they're request-scoped responses, not Pub/Sub messages).
type InAppNudgeType string

// String returns the wire string for switch-on-string compatibility at
// SQL `nudge_type IN ($)` sites + at consumer dispatch.
func (t InAppNudgeType) String() string { return string(t) }

// Canonical InAppNudgeType vocabulary (4 values).
//
// Each value maps to:
//   - one engine-side `InAppNudgeAuthor` class (Arc G2)
//   - one set of eligibility predicates against existing tables
//   - one anchor target (typed `InAppNudgeAnchorTarget`)
//   - one set of trigger contexts (typed `InAppNudgeContext`)
//   - 4 locale-localized copy strings (en/fi/sv/vi) via
//     `localization.translations` SoT
const (
	// InAppNudgeTypeTryScenariosFirstTime — roadmap-engaged learners
	// with sufficient vocabulary (≥20 user_item_statuses in learning/
	// known) who have NEVER opened scenarios. Loop C entry nudge.
	// Anchor: tab-quick-feature (juka). Contexts: home_idle,
	// roadmap_idle.
	InAppNudgeTypeTryScenariosFirstTime InAppNudgeType = "try_scenarios_first_time"

	// InAppNudgeTypeReviewBacklogIdle — learners with ≥15 due reviews
	// AND ≥2 days since last review, on a non-review surface. Loop B
	// re-entry. Highest population coverage (37.8% of active users).
	// Anchor: tab-exercises (Daily Challenge FAB target). Contexts:
	// home_idle, reading_session, conversation_session, video_session,
	// discovery_browse — EXPLICITLY NOT roadmap_idle (already adjacent).
	InAppNudgeTypeReviewBacklogIdle InAppNudgeType = "review_backlog_idle"

	// InAppNudgeTypeRoadmapCompletionistExplore — learners with ≥5
	// lessons completed AND 0 in-progress, on roadmap tab. Surfaces
	// "what next" after Loop E completion. Routes to articles (broadest
	// applicability across tracks). Anchor: tab-quick-feature.
	// Contexts: roadmap_idle ONLY (this is the specific "completionist
	// stuck" moment).
	InAppNudgeTypeRoadmapCompletionistExplore InAppNudgeType = "roadmap_completionist_explore"

	// InAppNudgeTypeConvoUserTryReading — scenario-engaged learners
	// (≥2 conversations) with 0 article reads. Loop F transfer entry.
	// Surfaces the comprehensible-input gap. Anchor: tab-quick-feature.
	// Contexts: home_idle, conversation_session.
	InAppNudgeTypeConvoUserTryReading InAppNudgeType = "convo_user_try_reading"
)

// AllInAppNudgeTypes is the canonical iteration order. Used by:
//   - V117 migration to derive the CHECK constraint values
//   - contract tests to assert Go↔Python parity
//   - engine `InAppNudgeService` to iterate priority-ordered authors
//
// Priority order (left-to-right, higher = render-first when multiple
// nudges are eligible for the same context):
//
//  1. review_backlog_idle (highest leverage — actionable retention)
//  2. roadmap_completionist_explore (clear "what next" moment)
//  3. try_scenarios_first_time (Loop C entry — exploratory)
//  4. convo_user_try_reading (lowest population — long-tail)
var AllInAppNudgeTypes = []InAppNudgeType{
	InAppNudgeTypeReviewBacklogIdle,
	InAppNudgeTypeRoadmapCompletionistExplore,
	InAppNudgeTypeTryScenariosFirstTime,
	InAppNudgeTypeConvoUserTryReading,
}

// IsValidInAppNudgeType reports whether the given value is a known
// canonical type. Producers + readers MUST call this at the API
// boundary before persisting OR rendering. Unknown values arrive when:
//
//   - mobile sends a stale enum value (e.g. an older app version that
//     remembers a retired nudge type)
//   - admin tooling typoes a value when authoring a new author
//   - test fixtures predate a vocabulary change
//
// Each path MUST treat unknown values as "ignore + log" rather than
// panic — same shape as Sweep ZK-B canonical narrow-on-unknown
// discipline.
func IsValidInAppNudgeType(t InAppNudgeType) bool {
	switch t {
	case InAppNudgeTypeTryScenariosFirstTime,
		InAppNudgeTypeReviewBacklogIdle,
		InAppNudgeTypeRoadmapCompletionistExplore,
		InAppNudgeTypeConvoUserTryReading:
		return true
	}
	return false
}
