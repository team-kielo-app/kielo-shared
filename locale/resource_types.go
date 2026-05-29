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

	// Engine-generated content (kielolearn-engine) — Phase 3.5
	ResourceTypeEngineExerciseInstruction = "engine.exercise.instruction"
	ResourceTypeEngineExerciseOption      = "engine.exercise.option"
	ResourceTypeEngineExerciseExplanation = "engine.exercise.explanation"
	ResourceTypeEngineChallengePrompt     = "engine.challenge.prompt"
	ResourceTypeEngineRoadmapLessonTitle  = "engine.roadmap.lesson_title"
	ResourceTypeEngineConceptHubSummary   = "engine.concept_hub.summary"

	// Curriculum (kielolearn-engine) — added 2026-05-29 to translate
	// track/level/chapter title+description on the mobile track-picker
	// + roadmap surfaces. Pre-fix /api/v3/curriculum/tracks emitted
	// `title: "New Track"` (canonical English) regardless of the
	// caller's support_language_code. See
	// docs/architecture/adr-007-localization-canonical-english.md.
	ResourceTypeEngineCurriculumTrackTitle         = "engine.curriculum.track_title"
	ResourceTypeEngineCurriculumTrackDescription   = "engine.curriculum.track_description"
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
	ResourceTypeEngineExerciseInstruction:          {},
	ResourceTypeEngineExerciseOption:               {},
	ResourceTypeEngineExerciseExplanation:          {},
	ResourceTypeEngineChallengePrompt:              {},
	ResourceTypeEngineRoadmapLessonTitle:           {},
	ResourceTypeEngineConceptHubSummary:            {},
	ResourceTypeEngineCurriculumTrackTitle:         {},
	ResourceTypeEngineCurriculumTrackDescription:   {},
	ResourceTypeEngineCurriculumLevelTitle:         {},
	ResourceTypeEngineCurriculumChapterTitle:       {},
	ResourceTypeEngineCurriculumChapterDescription: {},
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
