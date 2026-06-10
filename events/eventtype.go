// Package-level event-type constants for ADR-011 user-action spine
// producers.
//
// The canonical vocabulary lives in
//
//	kielo-events/internal/validate/vocabulary.go
//
// which is owned by the spine consumer. Producers in OTHER services
// can't import that internal package across module boundaries, so this
// file mirrors the constants here in `kielo-shared/events` where
// every producer already imports `UserActionEnvelope` from.
//
// Drift between this mirror and the spine vocabulary fails CI via
// tests/contract/event_vocabulary_contract_test.go — adding an event
// in one place without the other causes the contract test to fail
// before merge. Producers must use these typed constants instead of
// raw string literals so the compiler catches a typo at the call site
// rather than the spine silently rejecting the event at runtime.
//
// Adding a new event_type:
//
//  1. Amend ADR-011 §D1 with the new row + required props.
//  2. Add the constant + RequiredProps entry to
//     kielo-events/internal/validate/vocabulary.go.
//  3. Add the SAME constant (same name, same string) here.
//  4. Update the event_type → feature_name mapping in
//     kielo-events/internal/featuremap/feature_map.go.
//
// The contract test in step 3 enforces that the two const sets agree.
package events

// EventType is the typed alias producers pass into
// UserActionEnvelope.EventType. The wire format remains a string for
// SDK compatibility; this Go type just narrows the producer-side API
// surface so a stray literal can't be silently accepted.
type EventType string

// Content-consumption actions (ADR-011 D1.1).
const (
	EventArticleRead        EventType = "article.read"
	EventArticleViewed      EventType = "article.viewed"
	EventWordViewed         EventType = "word.viewed"
	EventWordLookedUp       EventType = "word.looked_up"
	EventGrammarViewed      EventType = "grammar.viewed"
	EventVideoWatched       EventType = "video.watched"
	EventVideoViewed        EventType = "video.viewed"
	EventParagraphTTSPlayed EventType = "paragraph.tts_played"
)

// Practice actions (ADR-011 D1.2).
const (
	EventExerciseAttempted            EventType = "exercise.attempted"
	EventExerciseCompleted            EventType = "exercise.completed"
	EventLessonStarted                EventType = "lesson.started"
	EventLessonCompleted              EventType = "lesson.completed"
	EventConversationSessionCompleted EventType = "conversation.session_completed"
	EventConversationTurnEvaluated    EventType = "conversation.turn_evaluated"
)

// Collection / curation actions (ADR-011 D1.3).
const (
	EventItemSaved            EventType = "item.saved"
	EventItemUnsaved          EventType = "item.unsaved"
	EventStudyListCreated     EventType = "study_list.created"
	EventStudyListUpdated     EventType = "study_list.updated"
	EventFlashcardDeckCreated EventType = "flashcard_deck.created"
)

// Engagement / lifecycle actions (ADR-011 D1.4).
const (
	EventAppHeartbeat            EventType = "app.heartbeat"
	EventAppSessionResumed       EventType = "app.session_resumed"
	EventStreakAdvanced          EventType = "streak.advanced"       // server-emitted
	EventStreakLost              EventType = "streak.lost"           // server-emitted
	EventGoalDailyCompleted      EventType = "goal.daily_completed"  // server-emitted
	EventFeatureLimitReached     EventType = "feature_limit.reached" // server-emitted
	EventRecommendationShown     EventType = "recommendation.shown"
	EventRecommendationTapped    EventType = "recommendation.tapped"
	EventRecommendationDismissed EventType = "recommendation.dismissed"
)

// AllEventTypes is the closed set producers can publish. Used by the
// contract test that pins this mirror against the spine vocabulary.
// Order matches ADR-011 D1.1-D1.4.
var AllEventTypes = []EventType{
	// D1.1 content-consumption
	EventArticleRead,
	EventArticleViewed,
	EventWordViewed,
	EventWordLookedUp,
	EventGrammarViewed,
	EventVideoWatched,
	EventVideoViewed,
	EventParagraphTTSPlayed,
	// D1.2 practice
	EventExerciseAttempted,
	EventExerciseCompleted,
	EventLessonStarted,
	EventLessonCompleted,
	EventConversationSessionCompleted,
	EventConversationTurnEvaluated,
	// D1.3 collection
	EventItemSaved,
	EventItemUnsaved,
	EventStudyListCreated,
	EventStudyListUpdated,
	EventFlashcardDeckCreated,
	// D1.4 engagement / lifecycle
	EventAppHeartbeat,
	EventAppSessionResumed,
	EventStreakAdvanced,
	EventStreakLost,
	EventGoalDailyCompleted,
	EventFeatureLimitReached,
	EventRecommendationShown,
	EventRecommendationTapped,
	EventRecommendationDismissed,
}
