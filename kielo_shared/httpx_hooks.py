"""httpx event hooks shared across Python Kielo services.

Register these on every outbound httpx.AsyncClient so service-to-service
calls forward the active learning language and (when wired) the trace
context, letting downstream services apply the correct per-language
search_path on their DB transactions.

Usage:

    from kielo_shared.httpx_hooks import inject_active_language_header

    client = httpx.AsyncClient(
        base_url=...,
        headers=...,
        event_hooks={"request": [inject_active_language_header]},
    )

The previous pattern of redefining this hook per-client (kielolearn-engine
had it; achievement_client and notification_event_client silently lacked
it, so the schema-per-language migration broke for those calls) is now
unnecessary.
"""
from __future__ import annotations

import httpx

from kielo_shared.locale_constants import LANGUAGE_ATTRIBUTE


# Canonical HTTP header name. Mirrors KieloLearningLanguageHeader on the
# Go side and the Pub/Sub LANGUAGE_ATTRIBUTE.
KIELO_LEARNING_LANGUAGE_HEADER = "X-Kielo-Learning-Language"


async def inject_active_language_header(request: httpx.Request) -> None:
    """httpx event hook — stamps the active learning language on the request.

    Reads the language from the kielo_shared contextvar set by the
    per-request middleware (or by background workers' explicit
    ``set_active_language`` scope). No-op when the contextvar is empty
    or when the header is already explicitly set.
    """
    # Imported lazily to avoid pulling SQLAlchemy at hook-registration time
    # — keeps this helper usable from minimal contexts.
    from kielo_shared.db_utils import get_active_language

    lang = get_active_language()
    if lang and KIELO_LEARNING_LANGUAGE_HEADER not in request.headers:
        request.headers[KIELO_LEARNING_LANGUAGE_HEADER] = lang


# LANGUAGE_ATTRIBUTE re-export as a convenience: callers using this hook
# usually also need the Pub/Sub-attribute spelling for upstream messages.
__all__ = [
    "KIELO_LEARNING_LANGUAGE_HEADER",
    "LANGUAGE_ATTRIBUTE",
    "inject_active_language_header",
]
