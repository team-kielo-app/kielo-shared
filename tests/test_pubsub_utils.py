"""Tests for pubsub_utils — Python mirror of the Go pubsubutil package.

Pinned contract:
  * event_attributes always stamps event_type.
  * event_attributes forwards the active learning language from the
    contextvar when set, never when unset.
  * inject_language_attribute does not override an existing value, so a
    caller can override the active language per-message (admin tooling,
    replay scripts).
"""
from __future__ import annotations

import pytest

from kielo_shared.db_utils import (
    reset_active_language,
    set_active_language,
)
from kielo_shared.pubsub_utils import (
    EVENT_TYPE_ATTRIBUTE,
    event_attributes,
    inject_language_attribute,
)
from kielo_shared.locale_constants import LANGUAGE_ATTRIBUTE


def test_event_attributes_stamps_event_type_only_when_no_language() -> None:
    attrs = event_attributes("conversation.started.v1")
    assert attrs == {EVENT_TYPE_ATTRIBUTE: "conversation.started.v1"}


def test_event_attributes_forwards_active_language() -> None:
    token = set_active_language("sv")
    try:
        attrs = event_attributes("learning.viewed_item.v1")
    finally:
        reset_active_language(token)
    assert attrs == {
        EVENT_TYPE_ATTRIBUTE: "learning.viewed_item.v1",
        LANGUAGE_ATTRIBUTE: "sv",
    }


def test_event_attributes_accepts_extra_kwargs() -> None:
    attrs = event_attributes("user.feature.used.v1", correlation_id="abc-123")
    assert attrs == {
        EVENT_TYPE_ATTRIBUTE: "user.feature.used.v1",
        "correlation_id": "abc-123",
    }


def test_inject_language_attribute_preserves_explicit_override() -> None:
    token = set_active_language("sv")
    try:
        attrs: dict[str, str] = {LANGUAGE_ATTRIBUTE: "fi"}
        inject_language_attribute(attrs)
    finally:
        reset_active_language(token)
    # Caller's explicit "fi" survives even when the contextvar says "sv".
    assert attrs[LANGUAGE_ATTRIBUTE] == "fi"


def test_inject_language_attribute_noop_without_active_language() -> None:
    attrs: dict[str, str] = {}
    inject_language_attribute(attrs)
    assert LANGUAGE_ATTRIBUTE not in attrs


def test_set_active_language_rejects_region_tagged_input() -> None:
    # The active-language contextvar is the schema-routing input; it must
    # only accept canonical base codes. Locale-shaped values must be
    # collapsed at the boundary before set_active_language is called.
    with pytest.raises(ValueError):
        set_active_language("sv-SE")
