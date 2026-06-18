package locale

// Resource-type constants for ADR-007's polymorphic
// `localization.dynamic_translations` table. Every call site that
// constructs a `localization.SourceRef` MUST use one of these constants
// — passing a string literal risks typos that fragment the namespace.
//
// Convention: dotted hierarchy, lowercase. `<service>.<entity>.<field>`
// where service is the owning domain. Adding a new resource type is a
// one-line PR plus the matching admin-ui / metrics dashboard updates.
//
// Cross-platform parity: identical set in
// `kielo-shared/kielo_shared/resource_types.py`.

const (
	// Articles (kielo-content-service) — Phase 3 / 4
	ResourceTypeArticleTitle       = "article.title"
	ResourceTypeArticleDescription = "article.description"
	ResourceTypeArticleParagraph   = "article.paragraph"

	// Conversation scenarios (kielo-convo + kielo-user-service) — Phase 7
	ResourceTypeScenarioTitle       = "scenario.title"
	ResourceTypeScenarioDescription = "scenario.description"

	// Conversation runtime (kielo-convo) — Phase 7
	ResourceTypeConvoTranscriptLine     = "convo.transcript.line"
	ResourceTypeConvoEvaluationFeedback = "convo.evaluation.feedback"

	// kielotv (kielo-content-service) — Phase 6
	ResourceTypeKtvCaptionCue  = "kielotv.caption.cue"
	ResourceTypeKtvMindmapNode = "kielotv.mindmap.node"
	// Sweep WW (2026-05-30): video title was an unregistered literal
	// at kielotv/metadata_localizer.go:259,316 and
	// daily_word_localizer.go:611,660. Now canonical.
	ResourceTypeKtvVideoTitle = "kielotv.title"

	// Engine-generated content (kielolearn-engine) — Phase 3.5
	ResourceTypeEngineExerciseInstruction = "engine.exercise.instruction"
	ResourceTypeEngineExerciseOption      = "engine.exercise.option"
	ResourceTypeEngineExerciseExplanation = "engine.exercise.explanation"
	ResourceTypeEngineChallengePrompt     = "engine.challenge.prompt"
	ResourceTypeEngineRoadmapLessonTitle  = "engine.roadmap.lesson_title"
	ResourceTypeEngineConceptHubSummary   = "engine.concept_hub.summary"

	// Sweep WW (2026-05-30) — formerly unregistered emission
	// namespaces caught by Sweep VV recon. Each was being used as a
	// string literal in production engine endpoints; now canonical.
	// See AGENTS.md Sweep WW row for the full drift trail.

	// roadmap_lesson — emitted by engine roadmap.py list+detail and
	// curriculum.py track-roadmap. Field keys: title_llm,
	// description_llm, category, lesson_content_json_llm. Canonical
	// post-Sweep-WW: list+detail+track-roadmap all use title_llm.
	ResourceTypeRoadmapLesson = "roadmap_lesson"

	// engine.roadmap.lesson.category — currently emitted by detail
	// endpoint as a separate resource_type (with the category string
	// itself as the resource_id) — closed-vocabulary translation
	// surface. Keep distinct from roadmap_lesson/category so the
	// admin can override categories independently of any specific
	// lesson row.
	ResourceTypeEngineRoadmapLessonCategory = "engine.roadmap.lesson.category"

	// engine.concept_hub.* — emitted by concept_hubs.py +
	// content_discovery_module.py. Per Sweep WW F2-F5 the summary +
	// title + description namespaces share underlying source strings
	// but stay separate at the seam level for cache independence
	// (summary teasers may live longer than full-detail rows).
	ResourceTypeEngineConceptHubTitle       = "engine.concept_hub.title"
	ResourceTypeEngineConceptHubDescription = "engine.concept_hub.description"
	ResourceTypeEngineConceptHubCategory    = "engine.concept_hub.category"

	// concept_hub — used by content_discovery_module.py and
	// concept_hubs.py persisted fields (title, description_llm,
	// common_mistakes, explanation_html_llm, etc.). Distinct from
	// the engine.concept_hub.* namespaces above because these are
	// persistent per-concept-hub fields (LLM-translated content)
	// rather than per-request seam translations.
	ResourceTypeConceptHub = "concept_hub"

	// exercise_deck — emitted by concept_hubs.py + lessons.py.
	// Field keys: title, description, session_goal.
	ResourceTypeExerciseDeck = "exercise_deck"

	// topic_list — emitted by topic_lists.py + Go content-service.
	// Field keys: display_name, description.
	ResourceTypeTopicList = "topic_list"

	// base_word — emitted by content.py + discovery.py + reviews.py +
	// placement.py + topic_lists.py + Go content-service +
	// Go user-service. Field key: meaning.
	ResourceTypeBaseWord = "base_word"

	// grammar_concept — emitted by content.py + discovery.py +
	// placement.py + reviews.py + Go user-service. Field key:
	// support_text. (The "meaning" field_key fallback in Go
	// user-service was removed by Sweep WW — dead read path.)
	ResourceTypeGrammarConcept = "grammar_concept"

	// word_deck — emitted by decks.py. Field keys: name, description.
	ResourceTypeWordDeck = "word_deck"

	// engine.challenge.error — emitted by challenges.py:969 as the
	// resource_id-bearing seam for non-fatal error messages on the
	// daily-challenge surface.
	ResourceTypeEngineChallengeError = "engine.challenge.error"

	// Curriculum (kielolearn-engine) — added 2026-05-29 to translate
	// track/level/chapter title+description on the mobile track-picker
	// + roadmap surfaces. Pre-fix /api/v3/curriculum/tracks emitted
	// `title: "New Track"` (canonical English) regardless of the
	// caller's support_language_code. See
	// docs/architecture/adr-007-localization-canonical-english.md.
	ResourceTypeEngineCurriculumTrackTitle       = "engine.curriculum.track_title"
	ResourceTypeEngineCurriculumTrackDescription = "engine.curriculum.track_description"
	// Arc 1A 2026-06-07: track audience surfaces on the picker card
	// ("Nurses + healthcare workers learning Finnish") and was emitted
	// raw English pre-Arc-1A. Added to the seam so vi/sv learners see
	// the audience localized through the same TTTT-F batch path as
	// title + description.
	ResourceTypeEngineCurriculumTrackAudience      = "engine.curriculum.track_audience"
	ResourceTypeEngineCurriculumLevelTitle         = "engine.curriculum.level_title"
	ResourceTypeEngineCurriculumChapterTitle       = "engine.curriculum.chapter_title"
	ResourceTypeEngineCurriculumChapterDescription = "engine.curriculum.chapter_description"

	// Notifications + emails (kielo-communications-service) — Phase 4.5
	ResourceTypeNotificationsTitle = "notifications.title"
	ResourceTypeNotificationsBody  = "notifications.body"
	ResourceTypeEmailSubject       = "email.subject"
	ResourceTypeEmailBody          = "email.body"

	// UI strings resolved through the supportregistry seam
	// (kielo-shared/locale/supportregistry) — ADR-008 Phase 5.
	// resource_id is the supportregistry.Key string verbatim; source_version
	// is sha256(english_seed)[:16] computed at registry-build time.
	ResourceTypeUIString = "ui.string"
)

// allResourceTypes is the authoritative set of valid resource_type
// values. Updated when constants above change. Used by IsValidResourceType.
var allResourceTypes = map[string]struct{}{
	ResourceTypeArticleTitle:                       {},
	ResourceTypeArticleDescription:                 {},
	ResourceTypeArticleParagraph:                   {},
	ResourceTypeScenarioTitle:                      {},
	ResourceTypeScenarioDescription:                {},
	ResourceTypeConvoTranscriptLine:                {},
	ResourceTypeConvoEvaluationFeedback:            {},
	ResourceTypeKtvCaptionCue:                      {},
	ResourceTypeKtvMindmapNode:                     {},
	ResourceTypeKtvVideoTitle:                      {},
	ResourceTypeEngineExerciseInstruction:          {},
	ResourceTypeEngineExerciseOption:               {},
	ResourceTypeEngineExerciseExplanation:          {},
	ResourceTypeEngineChallengePrompt:              {},
	ResourceTypeEngineChallengeError:               {},
	ResourceTypeEngineRoadmapLessonTitle:           {},
	ResourceTypeEngineRoadmapLessonCategory:        {},
	ResourceTypeEngineConceptHubSummary:            {},
	ResourceTypeEngineConceptHubTitle:              {},
	ResourceTypeEngineConceptHubDescription:        {},
	ResourceTypeEngineConceptHubCategory:           {},
	ResourceTypeEngineCurriculumTrackTitle:         {},
	ResourceTypeEngineCurriculumTrackDescription:   {},
	ResourceTypeEngineCurriculumTrackAudience:      {},
	ResourceTypeEngineCurriculumLevelTitle:         {},
	ResourceTypeEngineCurriculumChapterTitle:       {},
	ResourceTypeEngineCurriculumChapterDescription: {},
	ResourceTypeRoadmapLesson:                      {},
	ResourceTypeConceptHub:                         {},
	ResourceTypeExerciseDeck:                       {},
	ResourceTypeTopicList:                          {},
	ResourceTypeBaseWord:                           {},
	ResourceTypeGrammarConcept:                     {},
	ResourceTypeWordDeck:                           {},
	ResourceTypeNotificationsTitle:                 {},
	ResourceTypeNotificationsBody:                  {},
	ResourceTypeEmailSubject:                       {},
	ResourceTypeEmailBody:                          {},
	ResourceTypeUIString:                           {},
}

// IsValidResourceType returns true if rt is a recognized resource_type.
// Use at boundaries that take untrusted input (admin-ui filter params,
// CLI flags, etc.). Internal seam call sites should use the constants
// directly so the compiler enforces validity.
func IsValidResourceType(rt string) bool {
	_, ok := allResourceTypes[rt]
	return ok
}

// AllResourceTypes returns the full list of registered resource types.
// Returned slice is a snapshot; callers may sort/filter it freely.
func AllResourceTypes() []string {
	out := make([]string, 0, len(allResourceTypes))
	for rt := range allResourceTypes {
		out = append(out, rt)
	}
	return out
}
