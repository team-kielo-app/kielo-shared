"""httpx event hooks shared across Python Kielo services.

Register both hooks on every outbound httpx.AsyncClient so service-to-
service calls forward:

  * the active **learning language** (so downstream services apply the
    correct per-language search_path on their DB transactions), and
  * the active **trace context** (traceparent + x-request-id, so a
    single grep across docker logs walks the whole request chain
    web-ingest → cms → ingest-processor → cms → kielolearn-engine).

Usage:

    from kielo_shared.httpx_hooks import (
        inject_active_language_header,
        inject_trace_headers,
    )

    client = httpx.AsyncClient(
        base_url=...,
        headers=...,
        event_hooks={"request": [
            inject_active_language_header,
            inject_trace_headers,
        ]},
    )

The previous pattern of redefining the language hook per-client
(kielolearn-engine had it; achievement_client and notification_event_
client silently lacked it, so the schema-per-language migration broke
for those calls) is now unnecessary. The trace hook closes the same
gap for trace correlation — without it CMS handlers triggered by
inbound calls from kielolearn-engine create fresh trace_ids and the
downstream Pub/Sub events can't be linked back to the originator.
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


async def inject_trace_headers(request: httpx.Request) -> None:
    """httpx event hook — stamps traceparent and x-request-id on the request.

    Reads the active TraceContext from the contextvar populated by the
    per-request middleware (FastAPI's TraceMiddleware) or by background
    workers that bridged from a Pub/Sub message via
    :func:`kielo_shared.trace.set_current_trace_context`. No-op when no
    trace is active (CLI tools, module-load) or when the header is
    already explicitly set (caller override survives).

    Without this hook, the receiving service's RequestTracing middleware
    can't find a parent and starts a fresh trace — making it impossible
    to correlate the downstream call chain with the upstream initiator.
    """
    from kielo_shared.trace import (
        HEADER_CLIENT_TRACE_ID,
        HEADER_REQUEST_ID,
        HEADER_TRACEPARENT,
        current_trace_context,
        inject_headers,
    )

    tc = current_trace_context()
    # inject_headers is the canonical stamper; call it through a plain
    # dict so we can selectively merge into httpx.Headers (which is a
    # case-insensitive multidict — direct mutation is safe but goes
    # through the same setter contract this way).
    plain: dict[str, str] = {}
    inject_headers(plain, tc)
    for name in (HEADER_TRACEPARENT, HEADER_REQUEST_ID, HEADER_CLIENT_TRACE_ID):
        value = plain.get(name)
        if value and name not in request.headers:
            request.headers[name] = value


# LANGUAGE_ATTRIBUTE re-export as a convenience: callers using this hook
# usually also need the Pub/Sub-attribute spelling for upstream messages.
__all__ = [
    "KIELO_LEARNING_LANGUAGE_HEADER",
    "LANGUAGE_ATTRIBUTE",
    "inject_active_language_header",
    "inject_trace_headers",
]
