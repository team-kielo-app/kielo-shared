"""kielo_shared.events — Python typed-constant SoT for behavioral-event
and content-event vocabularies emitted by Python services.

Sweep ZJ-B.1 (2026-06-03): Python-side typed-vocabulary SoT module
covering 3 disjoint event-vocabulary domains:

  1. **Behavioral events** — the ``klearn.behavioral_event.v1``
     multiplexed-topic vocabulary emitted by kielolearn-engine.
     Inner ``event_type`` values flow through
     ``behavioral_event_service.record_event`` + the
     ``analytics_pipeline`` dispatcher. 5 distinct tiers:

     - **Tier A** (engine-internal producers): 5 wire strings emitted
       via ``BehavioralEventCreate(event_type=...)``.
     - **Tier B** (consumer-side dispatch): 5 additional wire strings
       branched on but not directly produced by engine code.
     - **Tier C** (ADR-011 adapter-translated): 19 legacy event_type
       values produced by ``to_behavioral_event()`` from canonical
       ``*.vN`` user-action events.
     - **Tier D** (topic-envelope event_types): 7 outer-envelope wire
       strings stamped via ``_publish_message(event_type=...)``.
     - **Tier E** (concept-hub notification): 2 sibling-vocabulary
       wire strings emitted by ``notification_event_client``.

  2. **Content events** — direct-publish ``*.processed.v1`` wire
     strings emitted by kielo-ingest-processor and consumed by
     kielo-cms outbox handler. 2 wire strings.

  3. **ItemType** — Python mirror of Go-side
     ``kielo-shared/vocab/itemtype.go`` (Sweep D vocabulary
     discipline). 7 PascalCase values pinning model-type wire shape.

Architectural shape (mirrors kielo_shared.errors / DDDDD-B3 pattern):

  - **BehavioralEventType** + **ContentEventType** + **ItemType** typed
    aliases (``str`` newtypes).
  - **Final[...]** annotations from PEP 591 — static-analysis flags
    accidental rebinds.
  - Iteration ``FrozenSet`` containers grouped by sub-vocabulary.
  - Explicit ``__all__`` export list.

Cross-language parity:

  Sweep ZJ-B.3 NEW contract test at
  ``tests/contract/behavioral_event_vocabulary_contract_test.go``
  scans kielolearn-engine Python source for literal event_type
  strings and asserts every literal is in this SoT or carries an
  inline ``# behavioral-vocabulary-allow: <reason>`` marker.

  The ItemType mirror is verified for parity with
  ``kielo-shared/vocab/itemtype.go`` by the existing
  ``TestItemTypeVocabularyMirrorMatchesPackage`` gate (extended in
  Sweep ZJ-B to scan Python literals as well).

Cross-vocabulary overlap with Go SoT: ZERO. Behavioral + content +
ItemType vocabularies are disjoint from Go-side
``publisheventtype.go`` (purchase / user.* / cms.* / media.*) and
``outboxeventtype.go`` (cms outbox drainer). No cross-language wire
string is duplicated across the two SoTs.

Note on architectural decisions documented in the ZJ recon:

  - The constant VALUE equals the wire string (drop-in replaceable
    for raw literals); we use ``Final[str]`` not ``StrEnum``.
  - The Tier C adapter-translated values appear in
    ``core/schemas/user_actions.py:_EVENT_TYPE_MAP`` rhs; the
    contract test treats those mapping rhs as registered producers
    (no per-mapping migration needed if all rhs values are in this
    SoT).
"""

from __future__ import annotations

from typing import Final, FrozenSet

# ----------------------------------------------------------------------
# Typed aliases
# ----------------------------------------------------------------------

BehavioralEventType = str
ContentEventType = str
ItemType = str

# ----------------------------------------------------------------------
# Tier A — engine-internal behavioral-event producer literals (5)
# Producers: services/session_state_service.py + services/
# conversation_drill_builder.py emit these via BehavioralEventCreate.
# ----------------------------------------------------------------------

EVENT_REVIEW_OUTCOME: Final[BehavioralEventType] = "review_outcome"
EVENT_EXERCISE_COMPLETED: Final[BehavioralEventType] = "exercise_completed"
EVENT_SESSION_SUMMARY: Final[BehavioralEventType] = "session_summary"
EVENT_CONVERSATION_SIGNAL: Final[BehavioralEventType] = "conversation_signal"
EVENT_ERROR_IDENTIFIED: Final[BehavioralEventType] = "error_identified"

# ----------------------------------------------------------------------
# Tier B — consumer-side dispatch (no engine-internal producer; arrives
# from ADR-011 adapter, mobile clients, or external POST).
# Consumers: services/behavioral_event_service.py +
# modules/analytics_pipeline_module.py.
# ----------------------------------------------------------------------

EVENT_ITEM_STATUS_CHANGED: Final[BehavioralEventType] = "item_status_changed"
EVENT_ITEM_SAVED: Final[BehavioralEventType] = "item_saved"
EVENT_CONTENT_VIEWED: Final[BehavioralEventType] = "content_viewed"
EVENT_RECOMMENDATION_SHOWN: Final[BehavioralEventType] = "recommendation_shown"
EVENT_RECOMMENDATION_TAPPED: Final[BehavioralEventType] = "recommendation_tapped"

# Cross-vocabulary key: ``learning.viewed_item.v1`` is a canonical
# ADR-011 user-action wire string that doubles as a behavioral-event
# dispatch key inside ``analytics_pipeline_module.event_handlers``.
# The bridge is ``viewed_item_listener.py`` consuming both forms.
EVENT_LEARNING_VIEWED_ITEM_V1: Final[BehavioralEventType] = "learning.viewed_item.v1"

# ----------------------------------------------------------------------
# Tier C — ADR-011 adapter-translated legacy event_types (19)
# These values appear in user_actions._EVENT_TYPE_MAP as the rhs of the
# (canonical-spine -> legacy-behavioral) mapping. They flow through the
# adapter path into BehavioralEvent.model_validate().
# ----------------------------------------------------------------------

EVENT_ARTICLE_READ: Final[BehavioralEventType] = "article_read"
EVENT_ARTICLE_VIEWED: Final[BehavioralEventType] = "article_viewed"
EVENT_WORD_VIEWED: Final[BehavioralEventType] = "word_viewed"
EVENT_DICTIONARY_LOOKUP: Final[BehavioralEventType] = "dictionary_lookup"
EVENT_GRAMMAR_CONCEPT_VIEWED: Final[BehavioralEventType] = "grammar_concept_viewed"
EVENT_KIELOTV_VIDEO_WATCHED: Final[BehavioralEventType] = "kielotv_video_watched"
EVENT_KIELOTV_VIDEO_VIEWED: Final[BehavioralEventType] = "kielotv_video_viewed"
EVENT_PARAGRAPH_TTS_PLAYED: Final[BehavioralEventType] = "paragraph_tts_played"
EVENT_EXERCISE_ATTEMPTED: Final[BehavioralEventType] = "exercise_attempted"
EVENT_LESSON_STARTED: Final[BehavioralEventType] = "lesson_started"
EVENT_LESSON_COMPLETED: Final[BehavioralEventType] = "lesson_completed"
EVENT_CONVERSATION_SESSION_COMPLETED: Final[BehavioralEventType] = "conversation_session_completed"
EVENT_CONVERSATION_TURN_EVALUATED: Final[BehavioralEventType] = "conversation_turn_evaluated"
EVENT_ITEM_UNSAVED: Final[BehavioralEventType] = "item_unsaved"
EVENT_STUDY_LIST_CREATED: Final[BehavioralEventType] = "study_list_created"
EVENT_STUDY_LIST_UPDATED: Final[BehavioralEventType] = "study_list_updated"
EVENT_FLASHCARD_DECK_CREATED: Final[BehavioralEventType] = "flashcard_deck_created"
EVENT_RECOMMENDATION_DISMISSED: Final[BehavioralEventType] = "recommendation_dismissed"

# ----------------------------------------------------------------------
# Tier D — topic-envelope event_type attributes (7)
# These are the OUTER envelope ``event_type`` stamped on Pub/Sub message
# attributes. Producers: core/messaging.py and sibling generation paths.
# ----------------------------------------------------------------------

TOPIC_EVENT_BEHAVIORAL_EVENT_V1: Final[BehavioralEventType] = "klearn.behavioral_event.v1"
TOPIC_EVENT_LESSON_GENERATION_V1: Final[BehavioralEventType] = "klearn.lesson.generation.requested.v1"
TOPIC_EVENT_CHALLENGE_GENERATION_V1: Final[BehavioralEventType] = "klearn.challenge.generation.requested.v1"
TOPIC_EVENT_CONCEPT_HUB_GENERATION_V1: Final[BehavioralEventType] = "klearn.concept_hub.generation.requested.v1"
TOPIC_EVENT_TOPIC_LIST_GENERATION_V1: Final[BehavioralEventType] = "klearn.topic_list.generation.requested.v1"
TOPIC_EVENT_EXERCISE_REVALIDATION_V1: Final[BehavioralEventType] = "kielo.exercise_revalidation.batch.v1"
TOPIC_EVENT_DATA_QUALITY_SWEEP_V1: Final[BehavioralEventType] = "kielo.data_quality.sweep.v1"

# ----------------------------------------------------------------------
# Tier E — concept-hub notification event_types (sibling vocabulary)
# Distinct topic — flows through ``notification_event_client.send_event``
# not the behavioral-event topic. Included for completeness so any
# producer literal in concept_hub_execution.py is registered.
# ----------------------------------------------------------------------

EVENT_CONCEPT_HUB_FAILED: Final[BehavioralEventType] = "kielolearn.concept_hub.failed"
EVENT_CONCEPT_HUB_GENERATED: Final[BehavioralEventType] = "kielolearn.concept_hub.generated"

# ----------------------------------------------------------------------
# Content events — direct-publish wire strings emitted by
# kielo-ingest-processor and consumed by kielo-cms outbox handler.
# Disjoint from Tier A-E (different topic, different envelope class).
# ----------------------------------------------------------------------

EVENT_CONTENT_ARTICLE_PROCESSED: Final[ContentEventType] = "content.article.processed.v1"
EVENT_CONTENT_VIDEO_PROCESSED: Final[ContentEventType] = "content.video.processed.v1"

# ----------------------------------------------------------------------
# ItemType — Python mirror of kielo-shared/vocab/itemtype.go
# Sweep D vocabulary discipline. PascalCase to match Go-side model
# type names. Pre-ZJ-B these were scattered as Literal["BaseWord",
# "GrammarConcept"] declarations across 15+ Python sites.
# ----------------------------------------------------------------------

ITEM_TYPE_BASE_WORD: Final[ItemType] = "BaseWord"
ITEM_TYPE_GRAMMAR_CONCEPT: Final[ItemType] = "GrammarConcept"
ITEM_TYPE_CONCEPT_HUB: Final[ItemType] = "ConceptHub"
ITEM_TYPE_ROADMAP_LESSON: Final[ItemType] = "RoadmapLesson"
ITEM_TYPE_TOPIC_LIST: Final[ItemType] = "TopicList"
ITEM_TYPE_ARTICLE: Final[ItemType] = "Article"
ITEM_TYPE_VIDEO: Final[ItemType] = "Video"

# ----------------------------------------------------------------------
# Iteration containers
# ----------------------------------------------------------------------

ALL_TIER_A_BEHAVIORAL_EVENTS: Final[FrozenSet[BehavioralEventType]] = frozenset({
    EVENT_REVIEW_OUTCOME,
    EVENT_EXERCISE_COMPLETED,
    EVENT_SESSION_SUMMARY,
    EVENT_CONVERSATION_SIGNAL,
    EVENT_ERROR_IDENTIFIED,
})

ALL_TIER_B_BEHAVIORAL_EVENTS: Final[FrozenSet[BehavioralEventType]] = frozenset({
    EVENT_ITEM_STATUS_CHANGED,
    EVENT_ITEM_SAVED,
    EVENT_CONTENT_VIEWED,
    EVENT_RECOMMENDATION_SHOWN,
    EVENT_RECOMMENDATION_TAPPED,
    EVENT_LEARNING_VIEWED_ITEM_V1,
})

ALL_TIER_C_BEHAVIORAL_EVENTS: Final[FrozenSet[BehavioralEventType]] = frozenset({
    EVENT_ARTICLE_READ,
    EVENT_ARTICLE_VIEWED,
    EVENT_WORD_VIEWED,
    EVENT_DICTIONARY_LOOKUP,
    EVENT_GRAMMAR_CONCEPT_VIEWED,
    EVENT_KIELOTV_VIDEO_WATCHED,
    EVENT_KIELOTV_VIDEO_VIEWED,
    EVENT_PARAGRAPH_TTS_PLAYED,
    EVENT_EXERCISE_ATTEMPTED,
    EVENT_LESSON_STARTED,
    EVENT_LESSON_COMPLETED,
    EVENT_CONVERSATION_SESSION_COMPLETED,
    EVENT_CONVERSATION_TURN_EVALUATED,
    EVENT_ITEM_UNSAVED,
    EVENT_STUDY_LIST_CREATED,
    EVENT_STUDY_LIST_UPDATED,
    EVENT_FLASHCARD_DECK_CREATED,
    EVENT_RECOMMENDATION_DISMISSED,
})

ALL_TIER_D_TOPIC_EVENTS: Final[FrozenSet[BehavioralEventType]] = frozenset({
    TOPIC_EVENT_BEHAVIORAL_EVENT_V1,
    TOPIC_EVENT_LESSON_GENERATION_V1,
    TOPIC_EVENT_CHALLENGE_GENERATION_V1,
    TOPIC_EVENT_CONCEPT_HUB_GENERATION_V1,
    TOPIC_EVENT_TOPIC_LIST_GENERATION_V1,
    TOPIC_EVENT_EXERCISE_REVALIDATION_V1,
    TOPIC_EVENT_DATA_QUALITY_SWEEP_V1,
})

ALL_TIER_E_NOTIFICATION_EVENTS: Final[FrozenSet[BehavioralEventType]] = frozenset({
    EVENT_CONCEPT_HUB_FAILED,
    EVENT_CONCEPT_HUB_GENERATED,
})

ALL_CONTENT_EVENTS: Final[FrozenSet[ContentEventType]] = frozenset({
    EVENT_CONTENT_ARTICLE_PROCESSED,
    EVENT_CONTENT_VIDEO_PROCESSED,
})

ALL_ITEM_TYPES: Final[FrozenSet[ItemType]] = frozenset({
    ITEM_TYPE_BASE_WORD,
    ITEM_TYPE_GRAMMAR_CONCEPT,
    ITEM_TYPE_CONCEPT_HUB,
    ITEM_TYPE_ROADMAP_LESSON,
    ITEM_TYPE_TOPIC_LIST,
    ITEM_TYPE_ARTICLE,
    ITEM_TYPE_VIDEO,
})


def all_behavioral_event_types() -> FrozenSet[BehavioralEventType]:
    """Union of every registered behavioral-event tier (A + B + C + D + E).

    Used by the contract gate's scanner to validate any producer
    literal is registered. Tier C values are included even though they
    are produced exclusively via the adapter path — the wire shape is
    identical to a direct producer, so the gate treats them uniformly.
    """
    return (
        ALL_TIER_A_BEHAVIORAL_EVENTS
        | ALL_TIER_B_BEHAVIORAL_EVENTS
        | ALL_TIER_C_BEHAVIORAL_EVENTS
        | ALL_TIER_D_TOPIC_EVENTS
        | ALL_TIER_E_NOTIFICATION_EVENTS
    )


def is_valid_behavioral_event_type(s: str) -> bool:
    """Return True when ``s`` exactly matches a registered constant."""
    return s in all_behavioral_event_types()


def is_valid_content_event_type(s: str) -> bool:
    """Return True when ``s`` exactly matches a registered content
    event_type."""
    return s in ALL_CONTENT_EVENTS


def is_valid_item_type(s: str) -> bool:
    """Return True when ``s`` exactly matches a registered ItemType
    PascalCase value. Mirrors Go ``vocab.IsValidItemType``."""
    return s in ALL_ITEM_TYPES


__all__ = [
    # Type aliases
    "BehavioralEventType",
    "ContentEventType",
    "ItemType",
    # Tier A
    "EVENT_REVIEW_OUTCOME",
    "EVENT_EXERCISE_COMPLETED",
    "EVENT_SESSION_SUMMARY",
    "EVENT_CONVERSATION_SIGNAL",
    "EVENT_ERROR_IDENTIFIED",
    # Tier B
    "EVENT_ITEM_STATUS_CHANGED",
    "EVENT_ITEM_SAVED",
    "EVENT_CONTENT_VIEWED",
    "EVENT_RECOMMENDATION_SHOWN",
    "EVENT_RECOMMENDATION_TAPPED",
    "EVENT_LEARNING_VIEWED_ITEM_V1",
    # Tier C
    "EVENT_ARTICLE_READ",
    "EVENT_ARTICLE_VIEWED",
    "EVENT_WORD_VIEWED",
    "EVENT_DICTIONARY_LOOKUP",
    "EVENT_GRAMMAR_CONCEPT_VIEWED",
    "EVENT_KIELOTV_VIDEO_WATCHED",
    "EVENT_KIELOTV_VIDEO_VIEWED",
    "EVENT_PARAGRAPH_TTS_PLAYED",
    "EVENT_EXERCISE_ATTEMPTED",
    "EVENT_LESSON_STARTED",
    "EVENT_LESSON_COMPLETED",
    "EVENT_CONVERSATION_SESSION_COMPLETED",
    "EVENT_CONVERSATION_TURN_EVALUATED",
    "EVENT_ITEM_UNSAVED",
    "EVENT_STUDY_LIST_CREATED",
    "EVENT_STUDY_LIST_UPDATED",
    "EVENT_FLASHCARD_DECK_CREATED",
    "EVENT_RECOMMENDATION_DISMISSED",
    # Tier D
    "TOPIC_EVENT_BEHAVIORAL_EVENT_V1",
    "TOPIC_EVENT_LESSON_GENERATION_V1",
    "TOPIC_EVENT_CHALLENGE_GENERATION_V1",
    "TOPIC_EVENT_CONCEPT_HUB_GENERATION_V1",
    "TOPIC_EVENT_TOPIC_LIST_GENERATION_V1",
    "TOPIC_EVENT_EXERCISE_REVALIDATION_V1",
    "TOPIC_EVENT_DATA_QUALITY_SWEEP_V1",
    # Tier E
    "EVENT_CONCEPT_HUB_FAILED",
    "EVENT_CONCEPT_HUB_GENERATED",
    # Content events
    "EVENT_CONTENT_ARTICLE_PROCESSED",
    "EVENT_CONTENT_VIDEO_PROCESSED",
    # ItemType
    "ITEM_TYPE_BASE_WORD",
    "ITEM_TYPE_GRAMMAR_CONCEPT",
    "ITEM_TYPE_CONCEPT_HUB",
    "ITEM_TYPE_ROADMAP_LESSON",
    "ITEM_TYPE_TOPIC_LIST",
    "ITEM_TYPE_ARTICLE",
    "ITEM_TYPE_VIDEO",
    # Iteration containers
    "ALL_TIER_A_BEHAVIORAL_EVENTS",
    "ALL_TIER_B_BEHAVIORAL_EVENTS",
    "ALL_TIER_C_BEHAVIORAL_EVENTS",
    "ALL_TIER_D_TOPIC_EVENTS",
    "ALL_TIER_E_NOTIFICATION_EVENTS",
    "ALL_CONTENT_EVENTS",
    "ALL_ITEM_TYPES",
    # Helpers
    "all_behavioral_event_types",
    "is_valid_behavioral_event_type",
    "is_valid_content_event_type",
    "is_valid_item_type",
]
