"""Pub/Sub attribute helpers — Python mirror of the Go ``pubsubutil`` package.

Publishers across the platform call :func:`event_attributes` to build the
attribute map for outbound messages. Consumers call
:func:`kielo_shared.locale_constants.language_from_attributes` to extract
the language from inbound messages. The two helpers stamp and read the
same attribute name (``learning_language_code``) so a message published
by any service is correctly scoped by any other service's consumer.

Why mirror the Go side: the Kielo platform has both Go and Python
publishers/consumers. Without a shared Python helper, every Python
publisher rolls its own attribute dict and forgets to forward the
language, leaving consumers unable to re-establish the per-language
search_path on their DB transactions.
"""
from __future__ import annotations

from typing import Optional

from kielo_shared.locale_constants import LANGUAGE_ATTRIBUTE

# Canonical attribute name carrying the event-type discriminator. Mirrors
# ``pubsubutil.EventTypeAttribute`` on the Go side so publishers in either
# language stamp the same key.
EVENT_TYPE_ATTRIBUTE: str = "event_type"


def _get_active_language() -> Optional[str]:
    """Read the active learning language from the shared contextvar.

    Imported lazily so this module doesn't pull SQLAlchemy in via
    ``db_utils`` at import time — keeps the helper usable from minimal
    publisher contexts that don't open DB sessions.
    """
    from kielo_shared.db_utils import get_active_language

    return get_active_language()


def inject_language_attribute(attrs: dict[str, str]) -> None:
    """Stamp the active learning language onto an attributes dict.

    No-op when the contextvar is unset or the attribute is already set
    (so per-call overrides — admin tooling, replay scripts — survive).
    Mutates ``attrs`` in place to mirror the Go helper's behavior.
    """
    if attrs is None:
        return
    if LANGUAGE_ATTRIBUTE in attrs:
        return
    lang = _get_active_language()
    if lang:
        attrs[LANGUAGE_ATTRIBUTE] = lang


def event_attributes(event_type: str, **extra: str) -> dict[str, str]:
    """Build a fresh attributes map carrying ``event_type`` plus the active
    language (when set) and any caller-supplied extras.

    Standard recipe for Python publishers:

        future = topic.publish(
            data=payload_bytes,
            **event_attributes("content.article.processed.v1"),
        )

    Returns a fresh dict; safe to call without holding a lock.
    """
    attrs: dict[str, str] = {EVENT_TYPE_ATTRIBUTE: event_type}
    for key, value in extra.items():
        if isinstance(value, str) and value:
            attrs[key] = value
    inject_language_attribute(attrs)
    from kielo_shared.trace import current_trace_context, inject_trace_attributes

    inject_trace_attributes(attrs, current_trace_context())
    return attrs


__all__ = [
    "EVENT_TYPE_ATTRIBUTE",
    "event_attributes",
    "inject_language_attribute",
]
