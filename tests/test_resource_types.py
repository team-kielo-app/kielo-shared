"""Tests for kielo_shared.resource_types — parity with the Go side."""

from __future__ import annotations

import pytest

from kielo_shared import resource_types as rt


def test_known_resource_types_validate() -> None:
    for value in (
        rt.ARTICLE_TITLE,
        rt.ARTICLE_PARAGRAPH,
        rt.SCENARIO_DESCRIPTION,
        rt.ENGINE_EXERCISE_INSTRUCTION,
        rt.NOTIFICATIONS_BODY,
    ):
        assert rt.is_valid_resource_type(value), value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "article.unknown_field",
        "Article.Title",  # case-sensitive
        "article",
        ".article.title",
    ],
)
def test_unknown_or_malformed_rejected(value: str) -> None:
    assert not rt.is_valid_resource_type(value)


def test_all_resource_types_has_expected_size() -> None:
    # Lower bound mirrors the Go test; tightens if/when constants are
    # added. Loose so adding a new constant doesn't fail the test.
    assert len(rt.ALL_RESOURCE_TYPES) >= 15


def test_naming_convention_lowercase_dotted() -> None:
    # Convention: lowercase, dot-separated when fully-qualified, no
    # leading/trailing dot.
    #
    # Sweep WW (2026-05-30) registered 7 short-form constants
    # without a dot separator (roadmap_lesson, concept_hub,
    # exercise_deck, topic_list, base_word, grammar_concept,
    # word_deck) because those were the EXISTING wire-shape values
    # in production `localization.dynamic_translations.resource_type`
    # rows pre-Sweep-WW — engine roadmap.py / concept_hubs.py /
    # exercise_deck_builder.py et al had been writing raw
    # short-form strings to the column for months before the SoT
    # module was lifted. Sweep WW chose to REGISTER the existing
    # wire vocabulary into the SoT rather than rename + migrate
    # ~9K production rows; the trade-off is documented in the
    # AGENTS Sweep WW row.
    #
    # The Go-side `TestResourceTypeNamingConvention` at
    # `locale/resource_types_test.go` accepts the same shape (it
    # checks lowercase + no-leading/trailing-dot but NOT presence
    # of any dot). The Python test was the drift relative to
    # Sweep WW — corrected here to match Go.
    short_form_allowed = frozenset(
        {
            "roadmap_lesson",
            "concept_hub",
            "exercise_deck",
            "topic_list",
            "base_word",
            "grammar_concept",
            "word_deck",
        }
    )
    for value in rt.ALL_RESOURCE_TYPES:
        assert value, "empty resource type registered"
        assert value == value.lower(), f"{value!r} is not lowercase"
        assert not value.startswith("."), f"{value!r} starts with a dot"
        assert not value.endswith("."), f"{value!r} ends with a dot"
        if "." not in value:
            assert value in short_form_allowed, (
                f"{value!r} has no namespace separator AND is not in the "
                f"Sweep WW short-form allowlist; either add a dotted "
                f"namespace OR document it in short_form_allowed (with "
                f"rationale linking to the wire-shape it preserves)"
            )
