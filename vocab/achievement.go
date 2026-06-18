// Sweep ZK-B (2026-06-03): typed-vocabulary SoT for achievement codes
// shared across user-service (writer + l10n table), comms-service
// (push/email dispatcher), kielolearn-engine Python (trigger emitter
// via HTTP), e2e tests (JSON body composition + SQL fixtures).
//
// Pre-ZK-B all 21 canonical codes were scattered as raw string literals
// across ~80 sites in 13 files. A single typo (e.g. `streaks_3` instead
// of `streak_3`) at any of the producer sites would silently no-op the
// badge award:
//
//  1. engine emits code via achievement_client.award_achievement
//  2. user-service handler queries achievement_definitions WHERE code = $1
//  3. zero rows → handler returns {awarded: false, "already_earned_or_not_found"}
//  4. engine's `if result.get("awarded")` branch is False → log.debug only
//  5. no Pub/Sub event, no push notification, no email, no badge in UI
//  6. user complains 3-day-streak badge never appeared; team has no
//     observability surface to debug — DEBUG-level log was never captured
//
// Sweep ZK-B closes the silent-failure class structurally: compile-time
// narrowing on the producer surface + cross-language parity gate + V005
// seed parity test = the next `streaks_3` typo fails at code review.
//
// 5th instance of the cross-language typed-vocab SoT pattern (after
// DDDDD-B3 error codes, SSS-C outbox event types, IIII publish event
// types, ZJ-B Python events/ItemType). Same shape as `itemtype.go`
// (Sweep D vocabulary) at the achievement-vocabulary layer.
package vocab

// AchievementCode is the closed vocabulary of canonical achievement
// codes, seeded by `database/migrations/V005__add_achievements.sql`
// at the `users.achievement_definitions.code` column.
//
// Values are lowercase snake_case with embedded numeric thresholds
// (`words_10`, `streak_3`, `top_5_percent`). Stable since V005 (2024);
// adding a new code requires a sibling Alembic/Flyway migration that
// INSERTs into `users.achievement_definitions` AND a corresponding
// constant + iteration-slice entry here.
//
// The contract test at
// `tests/contract/achievement_code_vocabulary_contract_test.go`
// asserts every V005 INSERT code appears here AND every constant here
// appears in V005 — bidirectional parity prevents drift in either
// direction.
type AchievementCode string

// String returns the wire string for switch-on-string compatibility
// at consumer dispatch sites. Producers can use the typed constant
// directly (it IS a string newtype) for compile-time narrowing.
func (c AchievementCode) String() string { return string(c) }

// Word-mastery achievements (5).
// Awarded by kielolearn-engine `achievement_service.py:_check_word_count`
// on every base-word save event.
const (
	AchievementCodeFirstWord AchievementCode = "first_word"
	AchievementCodeWords10   AchievementCode = "words_10"
	AchievementCodeWords50   AchievementCode = "words_50"
	AchievementCodeWords100  AchievementCode = "words_100"
	AchievementCodeWords500  AchievementCode = "words_500"
)

// Grammar-mastery achievements (3).
// Awarded by kielolearn-engine `achievement_service.py:_check_grammar_count`
// on every grammar-concept save event.
const (
	AchievementCodeFirstGrammar AchievementCode = "first_grammar"
	AchievementCodeGrammar10    AchievementCode = "grammar_10"
	AchievementCodeGrammar500   AchievementCode = "grammar_500"
)

// Exercise-completion achievements (3).
// Awarded by kielolearn-engine `achievement_service.py:_check_exercises_count`
// on every exercise_completed behavioral event.
const (
	AchievementCodeExercises100  AchievementCode = "exercises_100"
	AchievementCodeExercises500  AchievementCode = "exercises_500"
	AchievementCodeExercises1000 AchievementCode = "exercises_1000"
)

// Streak achievements (3).
// Awarded by kielolearn-engine `achievement_service.py:process_streak_updated`
// on streak-day-count milestone hits.
const (
	AchievementCodeStreak3  AchievementCode = "streak_3"
	AchievementCodeStreak7  AchievementCode = "streak_7"
	AchievementCodeStreak30 AchievementCode = "streak_30"
)

// Special achievements (2).
// Awarded by kielolearn-engine: concept_hub_creator on first concept-hub
// generation success; first_paying_user on first subscription purchase.
// Both have dedicated dispatch branches in
// `kielo-communications-service/internal/handlers/pubsub_handler.go`
// (concept_hub_creator → special push title) and
// `kielo-communications-service/internal/services/email_service.go`
// (first_paying_user → dedicated email template).
const (
	AchievementCodeConceptHubCreator AchievementCode = "concept_hub_creator"
	AchievementCodeFirstPayingUser   AchievementCode = "first_paying_user"
)

// Percentile-rank achievements (3).
// Awarded by batch leaderboard job — NOT emitted from
// engine's runtime path (`achievement_service.py` does not fire these).
const (
	AchievementCodeTop10Percent AchievementCode = "top_10_percent"
	AchievementCodeTop5Percent  AchievementCode = "top_5_percent"
	AchievementCodeTop1Percent  AchievementCode = "top_1_percent"
)

// Leaderboard winner achievements (2).
// Awarded by kielolearn-engine `achievement_service.py:process_leaderboard_winner`
// at line 430 via `code = f"top_learner_{period}"` f-string composition.
// The `period` parameter is `Literal["weekly", "monthly"]` — see
// CodeForLeaderboardPeriod() helper below.
const (
	AchievementCodeTopLearnerWeekly  AchievementCode = "top_learner_weekly"
	AchievementCodeTopLearnerMonthly AchievementCode = "top_learner_monthly"
)

// AllAchievementCodes is the canonical iteration order, grouped by
// category (word / grammar / exercise / streak / special / percentile /
// leaderboard). This ordering is the SoT-readable taxonomy — V005's
// historical INSERT order is incidental (grammar_500 was appended last
// at line 40 of V005, after the top_learner block).
//
// The contract test asserts bidirectional parity with V005's INSERT
// list, ordering-irrelevant.
var AllAchievementCodes = []AchievementCode{
	// Word mastery
	AchievementCodeFirstWord,
	AchievementCodeWords10,
	AchievementCodeWords50,
	AchievementCodeWords100,
	AchievementCodeWords500,
	// Grammar mastery
	AchievementCodeFirstGrammar,
	AchievementCodeGrammar10,
	AchievementCodeGrammar500,
	// Exercise completion
	AchievementCodeExercises100,
	AchievementCodeExercises500,
	AchievementCodeExercises1000,
	// Streak
	AchievementCodeStreak3,
	AchievementCodeStreak7,
	AchievementCodeStreak30,
	// Special
	AchievementCodeConceptHubCreator,
	AchievementCodeFirstPayingUser,
	// Percentile rank (batch leaderboard)
	AchievementCodeTop10Percent,
	AchievementCodeTop5Percent,
	AchievementCodeTop1Percent,
	// Leaderboard winner
	AchievementCodeTopLearnerWeekly,
	AchievementCodeTopLearnerMonthly,
}

// IsValidAchievementCode returns true when s exactly matches one of the
// 21 canonical codes. Producers parsing inbound user input (admin
// endpoints accepting arbitrary `achievement_code` POST params) should
// use this to validate before passing to repo/handler — protects against
// typo bleed-through at the API boundary.
func IsValidAchievementCode(s string) bool {
	for _, c := range AllAchievementCodes {
		if string(c) == s {
			return true
		}
	}
	return false
}

// CodeForLeaderboardPeriod is the typed replacement for the
// `f"top_learner_{period}"` f-string composition at
// `achievement_service.py:430`. Producer-side callers should use this
// helper instead of raw string concatenation so the typed-vocab
// invariant holds at compile time.
//
// Period values: "weekly" → AchievementCodeTopLearnerWeekly,
// "monthly" → AchievementCodeTopLearnerMonthly, anything else → empty
// AchievementCode (the caller MUST check IsValidAchievementCode before
// emit).
func CodeForLeaderboardPeriod(period string) AchievementCode {
	switch period {
	case "weekly":
		return AchievementCodeTopLearnerWeekly
	case "monthly":
		return AchievementCodeTopLearnerMonthly
	default:
		return ""
	}
}
