// Arc 1B v2 (2026-06-07): typed-vocabulary SoT for the
// `user_item_status.status` column shared across user-service (writer,
// `SaveItem` tx), kielolearn-engine (writer, `upsert_proficiencies`
// + `upsert_item_status`; reader, every CAM/skill_assessment/
// weakness_analyzer/internal_router site), e2e tests.
//
// Pre-Arc-1B-v2 the status string was a free-form column carrying 6
// distinct values produced by 4 writers across 2 languages:
//
//   PascalCase (engine-derived):  "Known" (218), "Learning" (1649), "Unknown" (87)
//   lowercase (mobile + user-svc): "learning" (45803), "new" (9644), "mastered" (137)
//
// 98%+ of production rows are lowercase. Arc 1B v1 normalized the
// CAMModule reader (one of ~8 reader sites) to handle both cases.
// Empirical recon found 2 OTHER reader sites still broken:
//
//   * services/weakness_analyzer.py:60 — `current_status == "Unknown"`
//     PascalCase-only check misses 98%+ of production rows. Wrong
//     weakness ranking, system-wide.
//   * services/skill_assessment.py:31-49 — `WHERE uis.status IN
//     ('learning', 'known')` lowercase-only misses 1649 "Learning" +
//     218 "Known" + 137 "mastered" = 2.9% under-count system-wide.
//
// Arc 1B v2 closes the structural drift class end-to-end:
//   1. This SoT module — closed-set canonical lowercase 3-value vocab
//      + a 4th "ignored" forward-compat value.
//   2. Cross-language Python mirror at
//      `kielo-shared/kielo_shared/vocab/user_item_status.py`.
//   3. V116 migration — backfill all 6 values to canonical lowercase
//      3-set + CHECK constraint enforcing the closed vocabulary.
//   4. Writer-side normalization at every producer site.
//   5. Reader-side fixes at the 2 Tier-1A bug sites.
//   6. Cross-language parity gate at
//      tests/contract/user_item_status_vocabulary_contract_test.go.
//
// Pattern: Sweep WW / SSS-B / SSS-C / IIII / DDDDD-B3 / ZK-B canonical
// typed-vocabulary SoT, with V116 CHECK constraint as the deploy-time
// anchor (the V005-parity gate analog for runtime-produced — vs
// deploy-seeded — vocabularies). Same pattern instance count as Arc 1A's
// audience seam + content-bridge surface_type at the user-state layer.
//
// 16th typed-vocab SoT module in kielo-shared/vocab/ (after Arc 1A
// content_bridge + scenarioSourceType + emailSubjectKey + pushKey +
// itemtype + achievement). The compounding-quality loop continues at
// 16 documented typed-vocab SoT instances.
package vocab

// UserItemStatus is the closed vocabulary of canonical learner-state
// values stored in `klearn_<lang>.user_item_statuses.status`. The
// status represents the LEARNER'S RELATIONSHIP to an item (BaseWord
// or GrammarConcept), not a write-source provenance tag.
//
// Three canonical bands + one forward-compat:
//
//   "unknown"  — learner has not yet engaged or proficiency below 0.3
//   "learning" — learner has engaged (mobile tap + saved-item) or
//                proficiency in [0.3, 0.7); the active practice band
//   "known"    — learner has demonstrated retention via review-outcome
//                or proficiency ≥ 0.7
//   "ignored"  — learner explicitly opted out of practicing this item
//                (forward-compat slot; no writer fires today)
//
// The lowercase canonical form is empirically the dominant production
// shape (98%+ of rows). Pre-Arc-1B-v2 the column also carried legacy
// PascalCase variants and a `"new"`/`"mastered"` band that meant the
// same thing semantically; V116 backfills them to the canonical set.
type UserItemStatus string

// String returns the wire string for switch-on-string compatibility at
// SQL `status IN ($)` sites + at consumer dispatch in Python (where
// `status_value.value` is the lowercase canonical).
func (s UserItemStatus) String() string { return string(s) }

// Canonical user-item-status vocabulary (4 values). All lowercase to
// match the empirical 98%+ dominant production shape.
const (
	UserItemStatusUnknown  UserItemStatus = "unknown"
	UserItemStatusLearning UserItemStatus = "learning"
	UserItemStatusKnown    UserItemStatus = "known"
	UserItemStatusIgnored  UserItemStatus = "ignored"
)

// AllUserItemStatuses is the canonical iteration order: the 3 active
// bands by ascending learner-proficiency, then the forward-compat
// "ignored" slot. The contract test asserts bidirectional parity with
// the V116 CHECK constraint clause, ordering-irrelevant.
var AllUserItemStatuses = []UserItemStatus{
	UserItemStatusUnknown,
	UserItemStatusLearning,
	UserItemStatusKnown,
	UserItemStatusIgnored,
}

// IsValidUserItemStatus returns true iff s is in the closed
// 4-value vocabulary. Used by `_lint-user-item-status-vocab-coverage`
// (future static gate) to flag drift at compile time and by writer
// helpers that defensively reject unknown inputs before persisting.
//
// Note: the legacy values "Known", "Learning", "Unknown", "new",
// "mastered" return FALSE — they must be normalized via
// NormalizeUserItemStatus first. Pre-V116 rows carrying these values
// will be backfilled by the migration; post-V116 the CHECK constraint
// rejects them.
func IsValidUserItemStatus(s string) bool {
	switch UserItemStatus(s) {
	case UserItemStatusUnknown,
		UserItemStatusLearning,
		UserItemStatusKnown,
		UserItemStatusIgnored:
		return true
	default:
		return false
	}
}

// NormalizeUserItemStatus maps any legacy or mixed-case status value
// to the canonical lowercase 4-value vocabulary. Returns the empty
// UserItemStatus when the input is empty OR cannot be mapped (caller
// MUST check IsValidUserItemStatus before persisting).
//
// Mapping table:
//
//	canonical (passthrough): "unknown", "learning", "known", "ignored"
//	legacy PascalCase:       "Unknown" → "unknown", "Learning" → "learning",
//	                         "Known" → "known", "Ignored" → "ignored"
//	semantic equivalents:    "new" → "unknown" (both mean "not yet
//	                         engaged"; user-service SaveItem writer
//	                         historically used "new"),
//	                         "mastered" → "known" (both mean "retained"; a
//	                         legacy writer abandoned 2025-12-25)
//
// V116 applies this same mapping in SQL to backfill the table before
// the CHECK constraint lands. The Go + Python helpers MUST stay in
// lockstep with the V116 mapping (cross-language parity gate enforces).
func NormalizeUserItemStatus(s string) UserItemStatus {
	switch s {
	case "unknown", "Unknown", "new", "New":
		return UserItemStatusUnknown
	case "learning", "Learning":
		return UserItemStatusLearning
	case "known", "Known", "mastered", "Mastered":
		return UserItemStatusKnown
	case "ignored", "Ignored":
		return UserItemStatusIgnored
	default:
		return ""
	}
}
