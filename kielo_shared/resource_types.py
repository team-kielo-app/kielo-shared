"""Resource-type constants for ADR-007's polymorphic
`localization.dynamic_translations` table.

Every call site that constructs a `localization.SourceRef` MUST use one
of these constants — passing a string literal risks typos that fragment
the namespace.

Convention: dotted hierarchy, lowercase. ``<service>.<entity>.<field>``
where service is the owning domain. Adding a new resource type is a
one-line PR plus the matching admin-ui / metrics dashboard updates.

Cross-platform parity: identical set in
``kielo-shared/locale/resource_types.go``.
"""

from __future__ import annotations

from typing import FrozenSet

# Articles (kielo-content-service) — Phase 3 / 4
ARTICLE_TITLE = "article.title"
ARTICLE_DESCRIPTION = "article.description"
ARTICLE_PARAGRAPH = "article.paragraph"

# Conversation scenarios (kielo-convo + kielo-user-service) — Phase 7
SCENARIO_TITLE = "scenario.title"
SCENARIO_DESCRIPTION = "scenario.description"

# Conversation runtime (kielo-convo) — Phase 7
CONVO_TRANSCRIPT_LINE = "convo.transcript.line"
CONVO_EVALUATION_FEEDBACK = "convo.evaluation.feedback"

# kielotv (kielo-content-service) — Phase 6
KTV_CAPTION_CUE = "kielotv.caption.cue"
KTV_MINDMAP_NODE = "kielotv.mindmap.node"
# Sweep WW (2026-05-30): video title was an unregistered literal at
# kielo-content-service/.../kielotv/metadata_localizer.go +
# daily_word_localizer.go. Now canonical.
KTV_VIDEO_TITLE = "kielotv.title"

# Engine-generated content (kielolearn-engine) — Phase 3.5
ENGINE_EXERCISE_INSTRUCTION = "engine.exercise.instruction"
ENGINE_EXERCISE_OPTION = "engine.exercise.option"
ENGINE_EXERCISE_EXPLANATION = "engine.exercise.explanation"
ENGINE_CHALLENGE_PROMPT = "engine.challenge.prompt"
ENGINE_CHALLENGE_ERROR = "engine.challenge.error"
ENGINE_ROADMAP_LESSON_TITLE = "engine.roadmap.lesson_title"
ENGINE_ROADMAP_LESSON_CATEGORY = "engine.roadmap.lesson.category"
ENGINE_CONCEPT_HUB_SUMMARY = "engine.concept_hub.summary"
ENGINE_CONCEPT_HUB_TITLE = "engine.concept_hub.title"
ENGINE_CONCEPT_HUB_DESCRIPTION = "engine.concept_hub.description"
ENGINE_CONCEPT_HUB_CATEGORY = "engine.concept_hub.category"

# Sweep WW (2026-05-30) — engine-level persistent emission namespaces.
# Pre-Sweep-WW these were string-literal-only in production. See
# AGENTS.md Sweep WW row.
ROADMAP_LESSON = "roadmap_lesson"
CONCEPT_HUB = "concept_hub"
EXERCISE_DECK = "exercise_deck"
TOPIC_LIST = "topic_list"
BASE_WORD = "base_word"
GRAMMAR_CONCEPT = "grammar_concept"
WORD_DECK = "word_deck"

# Curriculum (kielolearn-engine) — added 2026-05-29 to translate
# track/level/chapter title+description on the mobile track-picker
# + roadmap surfaces. Pre-fix /api/v3/curriculum/tracks emitted
# `title: "New Track"` (canonical English) regardless of the
# caller's support_language_code. See
# docs/architecture/adr-007-localization-canonical-english.md.
ENGINE_CURRICULUM_TRACK_TITLE = "engine.curriculum.track_title"
ENGINE_CURRICULUM_TRACK_DESCRIPTION = "engine.curriculum.track_description"
# Arc 1A 2026-06-07: track audience surfaces on the picker card
# ("Nurses + healthcare workers learning Finnish") and was emitted
# raw English pre-Arc-1A. Added to the seam so vi/sv learners see
# the audience localized through the same TTTT-F batch path as
# title + description.
ENGINE_CURRICULUM_TRACK_AUDIENCE = "engine.curriculum.track_audience"
ENGINE_CURRICULUM_LEVEL_TITLE = "engine.curriculum.level_title"
ENGINE_CURRICULUM_CHAPTER_TITLE = "engine.curriculum.chapter_title"
ENGINE_CURRICULUM_CHAPTER_DESCRIPTION = "engine.curriculum.chapter_description"

# Notifications + emails (kielo-communications-service) — Phase 4.5
NOTIFICATIONS_TITLE = "notifications.title"
NOTIFICATIONS_BODY = "notifications.body"
EMAIL_SUBJECT = "email.subject"
EMAIL_BODY = "email.body"

# UI strings resolved through the supportregistry seam — ADR-008 Phase 5.
# resource_id is the supportregistry key string verbatim;
# source_version is sha256(english_seed)[:16] computed at
# registry-build time.
UI_STRING = "ui.string"

# Authoritative set used by `is_valid_resource_type`. Update when
# constants above change.
ALL_RESOURCE_TYPES: FrozenSet[str] = frozenset(
    {
        ARTICLE_TITLE,
        ARTICLE_DESCRIPTION,
        ARTICLE_PARAGRAPH,
        SCENARIO_TITLE,
        SCENARIO_DESCRIPTION,
        CONVO_TRANSCRIPT_LINE,
        CONVO_EVALUATION_FEEDBACK,
        KTV_CAPTION_CUE,
        KTV_MINDMAP_NODE,
        KTV_VIDEO_TITLE,
        ENGINE_EXERCISE_INSTRUCTION,
        ENGINE_EXERCISE_OPTION,
        ENGINE_EXERCISE_EXPLANATION,
        ENGINE_CHALLENGE_PROMPT,
        ENGINE_CHALLENGE_ERROR,
        ENGINE_ROADMAP_LESSON_TITLE,
        ENGINE_ROADMAP_LESSON_CATEGORY,
        ENGINE_CONCEPT_HUB_SUMMARY,
        ENGINE_CONCEPT_HUB_TITLE,
        ENGINE_CONCEPT_HUB_DESCRIPTION,
        ENGINE_CONCEPT_HUB_CATEGORY,
        ENGINE_CURRICULUM_TRACK_TITLE,
        ENGINE_CURRICULUM_TRACK_DESCRIPTION,
        ENGINE_CURRICULUM_TRACK_AUDIENCE,
        ENGINE_CURRICULUM_LEVEL_TITLE,
        ENGINE_CURRICULUM_CHAPTER_TITLE,
        ENGINE_CURRICULUM_CHAPTER_DESCRIPTION,
        ROADMAP_LESSON,
        CONCEPT_HUB,
        EXERCISE_DECK,
        TOPIC_LIST,
        BASE_WORD,
        GRAMMAR_CONCEPT,
        WORD_DECK,
        NOTIFICATIONS_TITLE,
        NOTIFICATIONS_BODY,
        EMAIL_SUBJECT,
        EMAIL_BODY,
        UI_STRING,
    }
)


def is_valid_resource_type(rt: str) -> bool:
    """Return True if ``rt`` is a recognized resource_type.

    Use at boundaries that take untrusted input (admin-ui filter params,
    CLI flags, etc.). Internal seam call sites should use the module
    constants directly so the type checker enforces validity.
    """
    return rt in ALL_RESOURCE_TYPES
