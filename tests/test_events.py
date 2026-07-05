"""kielo_shared.events tests — Sweep ZJ-B.1 (2026-06-03).

Mirrors the kielo_shared.errors test pattern (Sweep DDDDD-B3). Pins:

- Vocabulary discipline (snake_case for behavioral events, PascalCase
  for ItemType, .vN suffix for content events).
- Cardinality + uniqueness across tiers (no two constants share a
  wire string).
- Iteration set membership matches declared frozensets.
- Helper functions behave correctly on edge cases.
"""

from __future__ import annotations

import re

import pytest

from kielo_shared import events


def test_behavioral_event_tiers_are_disjoint():
    """No wire string is registered in more than one tier (cardinality
    invariant — Sweep ZJ-B.1 SoT discipline)."""
    tiers = [
        events.ALL_TIER_A_BEHAVIORAL_EVENTS,
        events.ALL_TIER_B_BEHAVIORAL_EVENTS,
        events.ALL_TIER_C_BEHAVIORAL_EVENTS,
        events.ALL_TIER_D_TOPIC_EVENTS,
        events.ALL_TIER_E_NOTIFICATION_EVENTS,
    ]
    for i, lhs in enumerate(tiers):
        for j, rhs in enumerate(tiers):
            if i >= j:
                continue
            overlap = lhs & rhs
            assert not overlap, (
                f"tiers {i} and {j} share wire strings: {overlap}; "
                f"each behavioral wire string must belong to exactly "
                f"one tier"
            )


def test_behavioral_event_cardinality_matches_recon():
    """Sweep ZJ recon found 5 + 6 + 18 + 7 + 2 = 38 behavioral wire
    strings across the 5 tiers. The media-lifecycle platform adds
    TOPIC_EVENT_MEDIA_OWNER_DELETED_V1 to Tier D, bringing the total to
    5 + 6 + 18 + 8 + 2 = 39. Pin the count so a future drop surfaces the
    change explicitly."""
    assert len(events.ALL_TIER_A_BEHAVIORAL_EVENTS) == 5
    # Tier B includes LEARNING_VIEWED_ITEM_V1 (6 total; cross-vocabulary
    # ADR-011 wire string that doubles as behavioral dispatch key)
    assert len(events.ALL_TIER_B_BEHAVIORAL_EVENTS) == 6
    assert len(events.ALL_TIER_C_BEHAVIORAL_EVENTS) == 18
    # Tier D includes TOPIC_EVENT_MEDIA_OWNER_DELETED_V1
    # ("kielo.media.owner_deleted.v1"), the owner-deletion cascade trigger.
    assert len(events.ALL_TIER_D_TOPIC_EVENTS) == 8
    assert len(events.ALL_TIER_E_NOTIFICATION_EVENTS) == 2


def test_all_behavioral_event_types_union_is_complete():
    """``all_behavioral_event_types()`` must equal the union of all 5
    tier frozensets."""
    union = (
        events.ALL_TIER_A_BEHAVIORAL_EVENTS
        | events.ALL_TIER_B_BEHAVIORAL_EVENTS
        | events.ALL_TIER_C_BEHAVIORAL_EVENTS
        | events.ALL_TIER_D_TOPIC_EVENTS
        | events.ALL_TIER_E_NOTIFICATION_EVENTS
    )
    assert events.all_behavioral_event_types() == union


def test_content_events_versioned_format():
    """Content events follow the ``.vN`` versioning convention.
    Mirrors Sweep IIII Go-side discipline."""
    pattern = re.compile(r"^[a-z][a-z._0-9]+\.v\d+$")
    for wire in events.ALL_CONTENT_EVENTS:
        assert pattern.match(wire), f"content event {wire!r} must end .vN"


def test_item_types_are_pascal_case():
    """ItemType values must be PascalCase (Sweep D drift class — the
    `base_word` lowercase silently fell through PascalCase consumer
    switches). Mirrors Go-side vocab.IsValidItemType invariant."""
    pattern = re.compile(r"^[A-Z][A-Za-z]+$")
    for wire in events.ALL_ITEM_TYPES:
        assert pattern.match(wire), f"ItemType {wire!r} must be PascalCase"


def test_item_types_match_go_canonical_set():
    """Pins parity with kielo-shared/vocab/itemtype.go canonical set:
    BaseWord, GrammarConcept, ConceptHub, RoadmapLesson, TopicList,
    Article, Video. A future Go-side addition without the Python
    sibling will trip this test."""
    expected = frozenset({
        "BaseWord", "GrammarConcept", "ConceptHub", "RoadmapLesson",
        "TopicList", "Article", "Video",
    })
    assert events.ALL_ITEM_TYPES == expected


def test_behavioral_validator_accepts_known():
    """The is_valid_* helpers behave correctly on the canonical set."""
    assert events.is_valid_behavioral_event_type(events.EVENT_REVIEW_OUTCOME)
    assert events.is_valid_behavioral_event_type(events.TOPIC_EVENT_BEHAVIORAL_EVENT_V1)
    assert events.is_valid_behavioral_event_type(events.EVENT_CONCEPT_HUB_FAILED)


def test_behavioral_validator_rejects_unknown():
    """Unknown wire strings are rejected (closed-set invariant)."""
    assert not events.is_valid_behavioral_event_type("review_outcome.v999")
    assert not events.is_valid_behavioral_event_type("")
    assert not events.is_valid_behavioral_event_type("Review_outcome")  # case-sensitive


def test_content_validator_accepts_known():
    assert events.is_valid_content_event_type(events.EVENT_CONTENT_ARTICLE_PROCESSED)
    assert events.is_valid_content_event_type(events.EVENT_CONTENT_VIDEO_PROCESSED)


def test_content_validator_rejects_unknown():
    assert not events.is_valid_content_event_type("content.audio.processed.v1")
    assert not events.is_valid_content_event_type("")


def test_item_type_validator_accepts_known():
    assert events.is_valid_item_type(events.ITEM_TYPE_BASE_WORD)
    assert events.is_valid_item_type(events.ITEM_TYPE_ARTICLE)


def test_item_type_validator_rejects_unknown_and_drift():
    """The drift cases from Sweep D — lowercase, snake_case, mistyped
    — must be rejected so a producer using the helper catches drift
    at write time."""
    assert not events.is_valid_item_type("base_word")
    assert not events.is_valid_item_type("baseword")
    assert not events.is_valid_item_type("Baseword")
    assert not events.is_valid_item_type("")


def test_no_overlap_with_content_or_item_type():
    """Behavioral, content, ItemType vocabularies must be disjoint
    (architectural design decision recorded in module docstring)."""
    behavioral = events.all_behavioral_event_types()
    assert not (behavioral & events.ALL_CONTENT_EVENTS)
    assert not (behavioral & events.ALL_ITEM_TYPES)
    assert not (events.ALL_CONTENT_EVENTS & events.ALL_ITEM_TYPES)


@pytest.mark.parametrize(
    "wire_string,expected_tier",
    [
        ("review_outcome", "A"),
        ("item_status_changed", "B"),
        ("learning.viewed_item.v1", "B"),
        ("article_read", "C"),
        ("klearn.behavioral_event.v1", "D"),
        ("kielolearn.concept_hub.failed", "E"),
    ],
)
def test_canonical_wire_strings_in_correct_tier(wire_string: str, expected_tier: str):
    """Spot-check that the canonical wire strings recon identified
    land in the correct tier frozenset."""
    tier_map = {
        "A": events.ALL_TIER_A_BEHAVIORAL_EVENTS,
        "B": events.ALL_TIER_B_BEHAVIORAL_EVENTS,
        "C": events.ALL_TIER_C_BEHAVIORAL_EVENTS,
        "D": events.ALL_TIER_D_TOPIC_EVENTS,
        "E": events.ALL_TIER_E_NOTIFICATION_EVENTS,
    }
    assert wire_string in tier_map[expected_tier], (
        f"wire string {wire_string!r} should be in tier {expected_tier}"
    )
