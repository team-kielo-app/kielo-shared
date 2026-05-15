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
    for value in rt.ALL_RESOURCE_TYPES:
        assert value, "empty resource type registered"
        assert value == value.lower(), f"{value!r} is not lowercase"
        assert not value.startswith("."), f"{value!r} starts with a dot"
        assert not value.endswith("."), f"{value!r} ends with a dot"
        assert "." in value, f"{value!r} has no namespace separator"
