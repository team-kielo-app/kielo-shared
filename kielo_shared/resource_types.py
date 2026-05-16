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

# Engine-generated content (kielolearn-engine) — Phase 3.5
ENGINE_EXERCISE_INSTRUCTION = "engine.exercise.instruction"
ENGINE_EXERCISE_OPTION = "engine.exercise.option"
ENGINE_EXERCISE_EXPLANATION = "engine.exercise.explanation"
ENGINE_CHALLENGE_PROMPT = "engine.challenge.prompt"
ENGINE_ROADMAP_LESSON_TITLE = "engine.roadmap.lesson_title"
ENGINE_CONCEPT_HUB_SUMMARY = "engine.concept_hub.summary"

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
        ENGINE_EXERCISE_INSTRUCTION,
        ENGINE_EXERCISE_OPTION,
        ENGINE_EXERCISE_EXPLANATION,
        ENGINE_CHALLENGE_PROMPT,
        ENGINE_ROADMAP_LESSON_TITLE,
        ENGINE_CONCEPT_HUB_SUMMARY,
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
