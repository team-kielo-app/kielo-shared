"""Localization contract — Tier-1 SSOT for (resource_type, field_key) pairs.

Sweep WW (2026-05-30) recon enumerated every emission site of
user-facing localized text across the monorepo and found:

  - 14 distinct resource_type strings, ~30 distinct field_keys
  - 4 cases of field-key drift (same source field localized via
    different keys in different paths)
  - 12 dead canonical constants (declared but never used)
  - 1 read/write namespace mismatch (`convo.scenario.description`
    used as seam namespace vs `scenario.description` used as
    dual-write namespace — admin overrides never reached runtime)

This module is the declarative SSOT: every persistent localized
field that the engine emits is registered as a typed
``LocalizableField`` constant. Emission sites import the constant
and pass its ``resource_type`` + ``field_key`` to the seam fn
(``localize_persisted_text_field`` / ``localize_persisted_json_field``
/ ``localize_reusable_fields`` / ``localize_text_via_seam``).

A static gate (``scripts/diag-localization-contract.py``) fails on
any inline ``resource_type=`` / ``field_key=`` string passed to a
seam fn that isn't this module's constant. Baseline 0; canonical
vocabulary is enforced at lint time.

Naming convention:

  ``<service>.<entity>.<field>`` for the resource_type. Field keys
  follow ``<field_name>_llm`` for LLM-routed paths,
  ``<field_name>`` for opus-mt / reusable paths,
  ``<field_name>_html`` for HTML mode persistence.

Cross-language parity:

  Mirrored in ``kielo-shared/locale/localization_contract.go``
  (Go side) — keep both in sync. The two files share the same
  canonical resource_type set with ``kielo_shared/resource_types``
  (the existing simpler registry).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Literal

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

SeamFn = Literal[
    "localize_text_via_seam",
    "localize_persisted_text_field",
    "localize_persisted_gloss_field",
    "localize_persisted_json_field",
    "localize_reusable_fields",
    "localize_reusable_json_field",
]


@dataclass(frozen=True)
class LocalizableField:
    """Typed handle for a persistently-localized field.

    ``resource_type``: canonical resource_type from
    ``kielo_shared.resource_types``. The seam writes / reads
    ``localization.dynamic_translations`` rows with this value.

    ``field_key``: the key under which the seam stores this field
    within a row for the given resource_id. For
    ``localize_text_via_seam`` (single-text path) this is empty
    string; for ``localize_persisted_*`` it identifies the specific
    field on a multi-field resource (e.g. lesson has title_llm,
    description_llm, lesson_content_json_llm).

    ``seam_fn``: the canonical seam function for this field.
    Emission sites must use this seam, not a sibling — the field_key
    only makes sense for the matching seam shape.

    ``description``: human-readable description of the surface where
    this field appears. Used for documentation and admin-ui labeling.

    ``versioned``: True when the seam expects a source_version
    cache-busting key derived from the source text. False for
    closed-vocabulary fields where the resource_id IS the source
    string.
    """

    resource_type: str
    field_key: str
    seam_fn: SeamFn
    description: str
    versioned: bool = True

    def __post_init__(self) -> None:
        # Cross-check that resource_type is a registered canonical
        # constant. Catches typos in the contract file itself.
        from kielo_shared import resource_types

        if not resource_types.is_valid_resource_type(self.resource_type):
            raise ValueError(
                f"LocalizableField.resource_type={self.resource_type!r} "
                "is not registered in kielo_shared.resource_types."
            )


# ---------------------------------------------------------------------------
# Roadmap lesson — Sweep WW F1 canonical
# ---------------------------------------------------------------------------

# Post-Sweep-WW canonical: list_roadmap_lessons, get_roadmap_lesson,
# AND curriculum.py track-roadmap all use title_llm / description_llm.
# Pre-Sweep-WW the same source string lived in two cache rows:
#   (roadmap_lesson, lesson_id, "title_llm") — list+detail
#   (roadmap_lesson, lesson_id, "text") — curriculum track-roadmap
# Sweep WW unified on title_llm so admin overrides surface uniformly.
ROADMAP_LESSON_TITLE = LocalizableField(
    resource_type="roadmap_lesson",
    field_key="title_llm",
    seam_fn="localize_persisted_text_field",
    description="Lesson title shown in list, detail, and track-roadmap views.",
)

ROADMAP_LESSON_DESCRIPTION = LocalizableField(
    resource_type="roadmap_lesson",
    field_key="description_llm",
    seam_fn="localize_persisted_text_field",
    description="Lesson description shown in list, detail, and track-roadmap views.",
)

ROADMAP_LESSON_CONTENT_JSON = LocalizableField(
    resource_type="roadmap_lesson",
    field_key="lesson_content_json_llm",
    seam_fn="localize_persisted_json_field",
    description="Lesson content JSON tree (step content, options, etc.) — single cache row per lesson.",
)

ROADMAP_LESSON_CATEGORY = LocalizableField(
    resource_type="roadmap_lesson",
    field_key="category",
    seam_fn="localize_reusable_fields",
    description="Lesson category label (closed-vocabulary; list path).",
)


# ---------------------------------------------------------------------------
# Curriculum tracks/levels/chapters
# ---------------------------------------------------------------------------

CURRICULUM_TRACK_TITLE = LocalizableField(
    resource_type="engine.curriculum.track_title",
    field_key="title",
    seam_fn="localize_reusable_fields",
    description="Curriculum track title (e.g. 'Beginner Finnish A1-A2').",
)

CURRICULUM_TRACK_DESCRIPTION = LocalizableField(
    resource_type="engine.curriculum.track_description",
    field_key="description",
    seam_fn="localize_reusable_fields",
    description="Curriculum track description.",
)

CURRICULUM_LEVEL_TITLE = LocalizableField(
    resource_type="engine.curriculum.level_title",
    field_key="title",
    seam_fn="localize_reusable_fields",
    description="Curriculum level title within a track.",
)

CURRICULUM_CHAPTER_TITLE = LocalizableField(
    resource_type="engine.curriculum.chapter_title",
    field_key="title",
    seam_fn="localize_reusable_fields",
    description="Curriculum chapter title.",
)

CURRICULUM_CHAPTER_DESCRIPTION = LocalizableField(
    resource_type="engine.curriculum.chapter_description",
    field_key="description",
    seam_fn="localize_reusable_fields",
    description="Curriculum chapter description.",
)


# ---------------------------------------------------------------------------
# Concept hub
# ---------------------------------------------------------------------------

CONCEPT_HUB_TITLE = LocalizableField(
    resource_type="engine.concept_hub.title",
    field_key="",  # localize_text_via_seam uses empty field_key
    seam_fn="localize_text_via_seam",
    description="Concept-hub title (detail surface).",
)

CONCEPT_HUB_TITLE_PERSISTED = LocalizableField(
    resource_type="concept_hub",
    field_key="title",
    seam_fn="localize_persisted_text_field",
    description=(
        "Concept-hub title (discovery surface, persistent). Sweep WW: "
        "kept distinct from engine.concept_hub.title (text-as-resource_id "
        "via localize_text_via_seam) and engine.concept_hub.summary "
        "(teaser surface) because all three currently have independent "
        "cache rows; consolidation deferred to a future sweep."
    ),
)

CONCEPT_HUB_DESCRIPTION_PERSISTED = LocalizableField(
    resource_type="concept_hub",
    field_key="description_llm",
    seam_fn="localize_persisted_text_field",
    description="Concept-hub description (persistent LLM-translated).",
)

CONCEPT_HUB_EXPLANATION_HTML = LocalizableField(
    resource_type="concept_hub",
    field_key="explanation_html_llm",
    seam_fn="localize_persisted_text_field",
    description="Concept-hub explanation HTML (persistent LLM-translated).",
)

CONCEPT_HUB_COMMON_MISTAKES_JSON = LocalizableField(
    resource_type="concept_hub",
    field_key="common_mistakes_json_llm",
    seam_fn="localize_persisted_json_field",
    description="Concept-hub common mistakes JSON array.",
)

CONCEPT_HUB_EXAMPLES_JSON = LocalizableField(
    resource_type="concept_hub",
    field_key="examples_json",
    seam_fn="localize_reusable_json_field",
    description="Concept-hub examples JSON array.",
)


# ---------------------------------------------------------------------------
# Exercise deck
# ---------------------------------------------------------------------------

EXERCISE_DECK_TITLE = LocalizableField(
    resource_type="exercise_deck",
    field_key="title",
    seam_fn="localize_persisted_text_field",
    description="Exercise-deck title shown on concept-hub + practice-start surfaces.",
)

EXERCISE_DECK_DESCRIPTION = LocalizableField(
    resource_type="exercise_deck",
    field_key="description",
    seam_fn="localize_persisted_text_field",
    description="Exercise-deck description.",
)

EXERCISE_DECK_SESSION_GOAL = LocalizableField(
    resource_type="exercise_deck",
    field_key="session_goal",
    seam_fn="localize_persisted_text_field",
    description="Exercise-deck session-goal copy.",
)


# ---------------------------------------------------------------------------
# Topic list
# ---------------------------------------------------------------------------

TOPIC_LIST_DISPLAY_NAME = LocalizableField(
    resource_type="topic_list",
    field_key="display_name",
    seam_fn="localize_persisted_text_field",
    description="Topic-list display name.",
)

TOPIC_LIST_DESCRIPTION = LocalizableField(
    resource_type="topic_list",
    field_key="description",
    seam_fn="localize_persisted_text_field",
    description="Topic-list description.",
)


# ---------------------------------------------------------------------------
# Base word + grammar concept (dictionary surfaces)
# ---------------------------------------------------------------------------

BASE_WORD_MEANING = LocalizableField(
    resource_type="base_word",
    field_key="meaning",
    seam_fn="localize_persisted_gloss_field",
    description="Base-word meaning shown in dictionary, topic-lists, reviews, etc.",
)

GRAMMAR_CONCEPT_SUPPORT_TEXT = LocalizableField(
    resource_type="grammar_concept",
    field_key="support_text",
    seam_fn="localize_persisted_gloss_field",
    description="Grammar-concept meaning shown in dictionary, reviews, etc.",
)


# ---------------------------------------------------------------------------
# Word deck
# ---------------------------------------------------------------------------

WORD_DECK_NAME = LocalizableField(
    resource_type="word_deck",
    field_key="name",
    seam_fn="localize_reusable_fields",
    description="Word-deck name (reusable-fields batched path).",
)

WORD_DECK_DESCRIPTION = LocalizableField(
    resource_type="word_deck",
    field_key="description",
    seam_fn="localize_reusable_fields",
    description="Word-deck description (reusable-fields batched path).",
)


# ---------------------------------------------------------------------------
# Engine emission-only seam refs (resource_id = source string)
# ---------------------------------------------------------------------------
# These use localize_text_via_seam where the seam derives the cache
# key from the source text itself rather than a stable resource_id.
# Used for closed-vocabulary translations and ad-hoc text.

ENGINE_ROADMAP_LESSON_CATEGORY_SEAM = LocalizableField(
    resource_type="engine.roadmap.lesson.category",
    field_key="",
    seam_fn="localize_text_via_seam",
    description="Lesson category (detail surface — text-as-resource_id).",
)

ENGINE_CONCEPT_HUB_SUMMARY = LocalizableField(
    resource_type="engine.concept_hub.summary",
    field_key="",
    seam_fn="localize_text_via_seam",
    description="Concept-hub summary teaser (text-as-resource_id).",
)

ENGINE_CONCEPT_HUB_DESCRIPTION_SEAM = LocalizableField(
    resource_type="engine.concept_hub.description",
    field_key="",
    seam_fn="localize_text_via_seam",
    description="Concept-hub description (summary surface — text-as-resource_id).",
)

ENGINE_CONCEPT_HUB_CATEGORY = LocalizableField(
    resource_type="engine.concept_hub.category",
    field_key="",
    seam_fn="localize_text_via_seam",
    description="Concept-hub category badge (text-as-resource_id).",
)

ENGINE_CHALLENGE_ERROR = LocalizableField(
    resource_type="engine.challenge.error",
    field_key="",
    seam_fn="localize_text_via_seam",
    description="Daily-challenge non-fatal error messages (text-as-resource_id).",
)

# Sweep WW (2026-05-30) — engine.exercise.explanation was a dead
# canonical constant pre-Sweep-WW; resurrected here for the
# SubmissionResult.explanation seam routing (sessions.py).
ENGINE_EXERCISE_EXPLANATION = LocalizableField(
    resource_type="engine.exercise.explanation",
    field_key="",
    seam_fn="localize_text_via_seam",
    description="Exercise explanation shown as post-submission feedback.",
)


# ---------------------------------------------------------------------------
# Chapter title seam-bound emission (lesson endpoints)
# ---------------------------------------------------------------------------

# Sweep VV/WW: emitted by roadmap.py:list_roadmap_lessons +
# get_roadmap_lesson via localize_text_via_seam — seam keys by
# (resource_type, resource_id=chapter_id). Shares the underlying
# resource_type with the localize_reusable_fields path in
# curriculum.py:573 BUT uses an empty field_key. Both rows can
# coexist; admin override on either row is independently applied.
CURRICULUM_CHAPTER_TITLE_SEAM = LocalizableField(
    resource_type="engine.curriculum.chapter_title",
    field_key="",
    seam_fn="localize_text_via_seam",
    description="Chapter title emitted on the lesson list/detail surface.",
)


# ---------------------------------------------------------------------------
# kielotv (Go content-service mirror — used by Python recon only)
# ---------------------------------------------------------------------------

KTV_VIDEO_TITLE = LocalizableField(
    resource_type="kielotv.title",
    field_key="",
    seam_fn="localize_text_via_seam",
    description="kielotv video title (kielo-content-service writer).",
)

KTV_CAPTION_CUE_SUPPORT_TEXT = LocalizableField(
    resource_type="kielotv.caption.cue",
    field_key="support_text",
    seam_fn="localize_persisted_text_field",
    description="kielotv caption cue support-language translation.",
)


# ---------------------------------------------------------------------------
# Scenario (kielo-convo writer + reader)
# ---------------------------------------------------------------------------

SCENARIO_TITLE = LocalizableField(
    resource_type="scenario.title",
    field_key="",
    seam_fn="localize_text_via_seam",
    description="Conversation-scenario title (dual-write keyspace).",
)

SCENARIO_DESCRIPTION = LocalizableField(
    resource_type="scenario.description",
    field_key="",
    seam_fn="localize_text_via_seam",
    description="Conversation-scenario description (Sweep WW unified read/write keyspace).",
)


# ---------------------------------------------------------------------------
# Notifications + email (canonical via UI string seam)
# ---------------------------------------------------------------------------

UI_STRING = LocalizableField(
    resource_type="ui.string",
    field_key="",
    seam_fn="localize_text_via_seam",
    description="UI string resolved via supportregistry seam (ADR-008).",
    versioned=False,  # source_version is computed from supportregistry seed
)


# ---------------------------------------------------------------------------
# Authoritative set
# ---------------------------------------------------------------------------

ALL_LOCALIZABLE_FIELDS: FrozenSet[LocalizableField] = frozenset(
    {
        ROADMAP_LESSON_TITLE,
        ROADMAP_LESSON_DESCRIPTION,
        ROADMAP_LESSON_CONTENT_JSON,
        ROADMAP_LESSON_CATEGORY,
        CURRICULUM_TRACK_TITLE,
        CURRICULUM_TRACK_DESCRIPTION,
        CURRICULUM_LEVEL_TITLE,
        CURRICULUM_CHAPTER_TITLE,
        CURRICULUM_CHAPTER_DESCRIPTION,
        CURRICULUM_CHAPTER_TITLE_SEAM,
        CONCEPT_HUB_TITLE,
        CONCEPT_HUB_TITLE_PERSISTED,
        CONCEPT_HUB_DESCRIPTION_PERSISTED,
        CONCEPT_HUB_EXPLANATION_HTML,
        CONCEPT_HUB_COMMON_MISTAKES_JSON,
        CONCEPT_HUB_EXAMPLES_JSON,
        EXERCISE_DECK_TITLE,
        EXERCISE_DECK_DESCRIPTION,
        EXERCISE_DECK_SESSION_GOAL,
        TOPIC_LIST_DISPLAY_NAME,
        TOPIC_LIST_DESCRIPTION,
        BASE_WORD_MEANING,
        GRAMMAR_CONCEPT_SUPPORT_TEXT,
        WORD_DECK_NAME,
        WORD_DECK_DESCRIPTION,
        ENGINE_ROADMAP_LESSON_CATEGORY_SEAM,
        ENGINE_CONCEPT_HUB_SUMMARY,
        ENGINE_CONCEPT_HUB_DESCRIPTION_SEAM,
        ENGINE_CONCEPT_HUB_CATEGORY,
        ENGINE_CHALLENGE_ERROR,
        ENGINE_EXERCISE_EXPLANATION,
        KTV_VIDEO_TITLE,
        KTV_CAPTION_CUE_SUPPORT_TEXT,
        SCENARIO_TITLE,
        SCENARIO_DESCRIPTION,
        UI_STRING,
    }
)


# Lookup: (resource_type, field_key) -> LocalizableField. Used by the
# static gate to verify call-site arguments match a registered field.
LOCALIZABLE_FIELDS_BY_KEY: dict[tuple[str, str], LocalizableField] = {
    (f.resource_type, f.field_key): f for f in ALL_LOCALIZABLE_FIELDS
}


def lookup(resource_type: str, field_key: str = "") -> LocalizableField | None:
    """Return the registered LocalizableField matching the (resource_type,
    field_key) pair, or None if not registered.

    Use at runtime to convert (rt, fk) tuples back to the typed handle
    — e.g. for telemetry labeling or admin-ui display.
    """
    return LOCALIZABLE_FIELDS_BY_KEY.get((resource_type, field_key))


__all__ = [
    "LocalizableField",
    "SeamFn",
    "ALL_LOCALIZABLE_FIELDS",
    "LOCALIZABLE_FIELDS_BY_KEY",
    "lookup",
    # All field constants
    "ROADMAP_LESSON_TITLE",
    "ROADMAP_LESSON_DESCRIPTION",
    "ROADMAP_LESSON_CONTENT_JSON",
    "ROADMAP_LESSON_CATEGORY",
    "CURRICULUM_TRACK_TITLE",
    "CURRICULUM_TRACK_DESCRIPTION",
    "CURRICULUM_LEVEL_TITLE",
    "CURRICULUM_CHAPTER_TITLE",
    "CURRICULUM_CHAPTER_DESCRIPTION",
    "CURRICULUM_CHAPTER_TITLE_SEAM",
    "CONCEPT_HUB_TITLE",
    "CONCEPT_HUB_TITLE_PERSISTED",
    "CONCEPT_HUB_DESCRIPTION_PERSISTED",
    "CONCEPT_HUB_EXPLANATION_HTML",
    "CONCEPT_HUB_COMMON_MISTAKES_JSON",
    "CONCEPT_HUB_EXAMPLES_JSON",
    "EXERCISE_DECK_TITLE",
    "EXERCISE_DECK_DESCRIPTION",
    "EXERCISE_DECK_SESSION_GOAL",
    "TOPIC_LIST_DISPLAY_NAME",
    "TOPIC_LIST_DESCRIPTION",
    "BASE_WORD_MEANING",
    "GRAMMAR_CONCEPT_SUPPORT_TEXT",
    "WORD_DECK_NAME",
    "WORD_DECK_DESCRIPTION",
    "ENGINE_ROADMAP_LESSON_CATEGORY_SEAM",
    "ENGINE_CONCEPT_HUB_SUMMARY",
    "ENGINE_CONCEPT_HUB_DESCRIPTION_SEAM",
    "ENGINE_CONCEPT_HUB_CATEGORY",
    "ENGINE_CHALLENGE_ERROR",
    "ENGINE_EXERCISE_EXPLANATION",
    "KTV_VIDEO_TITLE",
    "KTV_CAPTION_CUE_SUPPORT_TEXT",
    "SCENARIO_TITLE",
    "SCENARIO_DESCRIPTION",
    "UI_STRING",
]
