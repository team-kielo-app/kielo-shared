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
        inject_active_language_query,
        inject_trace_headers,
    )

    client = httpx.AsyncClient(
        base_url=...,
        headers=...,
        event_hooks={"request": [
            inject_active_language_query,
            inject_trace_headers,
        ]},
    )
"""

from __future__ import annotations

import httpx

from kielo_shared.locale_constants import LANGUAGE_ATTRIBUTE


# Canonical query parameter name. Mirrors LearningLanguageQueryParam on
# the Go side and the Pub/Sub LANGUAGE_ATTRIBUTE.
LEARNING_LANGUAGE_QUERY_PARAM = "learning_language_code"

# Canonical service-to-service header (ADR-006 §3). Mirrors
# `LearningLanguageHeader` exported by kielo-shared/observe/httputil
# on the Go side. Paired with the query param for defense-in-depth:
# downstream services try the query first, then the header, so neither
# a proxy that strips one nor a misconfigured load balancer can lose
# the active learning language between hops.
LEARNING_LANGUAGE_HEADER = "X-Kielo-Learning-Language"

# Sweep SSSS-C: support-language wire constants — sibling to the
# learning-language pair above. Mirrors `SupportLanguageQueryParam` +
# `SupportLanguageHeader` exported by kielo-shared/observe/httputil
# on the Go side (Sweep QQQQ). When the engine calls back into Go
# services (content-service /api/v3/* paths that re-fetch localized
# content while processing a user request) the support language must
# flow through; pre-SSSS-C only the inbound resolver populated the
# contextvar, outbound httpx clients dropped it.
SUPPORT_LANGUAGE_QUERY_PARAM = "support_language_code"
SUPPORT_LANGUAGE_HEADER = "X-Kielo-Support-Language"


async def inject_active_language_query(request: httpx.Request) -> None:
    """httpx event hook — stamps the active learning language on the request
    as BOTH a `learning_language_code` query parameter AND an
    `X-Kielo-Learning-Language` header (ADR-006 §3).

    Reads the language from the kielo_shared contextvar set by the
    per-request middleware (or by background workers' explicit
    ``set_active_language`` scope). No-op when the contextvar is empty
    or when the corresponding channel is already explicitly set.
    """
    _stamp_active_language(request)


async def inject_active_support_language_query(request: httpx.Request) -> None:
    """httpx event hook — stamps the active support (UI/translation)
    language on the request as BOTH a `support_language_code` query
    parameter AND an `X-Kielo-Support-Language` header.

    Sweep SSSS-C canonical: Python sibling of the Go-side QQQQ shared
    helper (`ApplySupportLanguageQuery` + `ApplySupportLanguageHeader`
    wired into `PrepareInternalJSONRequest`). Engine calls back into
    content-service / cms via httpx clients (e.g. paragraph snippet
    fetches during enrichment, concept-hub re-localization) — pre-
    SSSS-C those calls dropped the support language signal because
    only the inbound `get_support_language` FastAPI dep populated the
    contextvar.

    Reads from `kielo_shared.db_utils.get_active_support_language`,
    populated by the per-request FastAPI middleware (or explicitly by
    background workers that need to scope a re-call to the user's
    locale). No-op when empty or when caller pre-set the channel.
    """
    _stamp_active_support_language(request)


async def inject_trace_headers(request: httpx.Request) -> None:
    """httpx event hook — stamps traceparent and x-request-id on the request.

    Reads the active TraceContext from the contextvar populated by the
    per-request middleware (FastAPI's TraceMiddleware) or by background
    workers that bridged from a Pub/Sub message via
    :func:`kielo_shared.trace.set_current_trace_context`. No-op when no
    trace is active (CLI tools, module-load) or when the header is
    already explicitly set (caller override survives).
    """
    _stamp_trace_headers(request)


def _stamp_active_language(request: httpx.Request) -> None:
    """Body shared between the sync and async language hooks.

    Stamps the active learning language on BOTH:
      * URL query param `learning_language_code` — lower-precedence
        companion that survives even when proxies strip custom headers.
      * Header `X-Kielo-Learning-Language` — canonical service-to-service
        channel (ADR-006 §3).

    Each channel is set-if-missing so an explicit per-call override
    (admin tooling inspecting cross-language data) survives. The two
    channels are independent: a caller that pre-set only the header
    still gets the query param stamped from ctx, and vice versa.
    """
    from kielo_shared.db_utils import get_active_language

    lang = get_active_language()
    if not lang:
        return
    url = request.url
    if not url.params.get(LEARNING_LANGUAGE_QUERY_PARAM):
        request.url = url.copy_merge_params({LEARNING_LANGUAGE_QUERY_PARAM: lang})
    if LEARNING_LANGUAGE_HEADER not in request.headers:
        request.headers[LEARNING_LANGUAGE_HEADER] = lang


def _stamp_active_support_language(request: httpx.Request) -> None:
    """Body shared between the sync and async support-language hooks.

    Stamps the active support (UI/translation) language on BOTH:
      * URL query param `support_language_code` — engine endpoints
        consume this via `kielo_shared.locale.fastapi.get_support_language`
        which honors query first then `Accept-Language`.
      * Header `X-Kielo-Support-Language` — canonical service-to-service
        channel (Sweep QQQQ Go-side mirror).

    Each channel is set-if-missing for caller-override survival.
    Sweep SSSS-C: sibling to `_stamp_active_language`.
    """
    from kielo_shared.db_utils import get_active_support_language

    code = get_active_support_language()
    if not code:
        return
    url = request.url
    if not url.params.get(SUPPORT_LANGUAGE_QUERY_PARAM):
        request.url = url.copy_merge_params({SUPPORT_LANGUAGE_QUERY_PARAM: code})
    if SUPPORT_LANGUAGE_HEADER not in request.headers:
        request.headers[SUPPORT_LANGUAGE_HEADER] = code


def _stamp_trace_headers(request: httpx.Request) -> None:
    """Body shared between the sync and async trace hooks."""
    from kielo_shared.trace import (
        HEADER_CLIENT_TRACE_ID,
        HEADER_REQUEST_ID,
        HEADER_TRACEPARENT,
        current_trace_context,
        inject_headers,
    )

    tc = current_trace_context()
    plain: dict[str, str] = {}
    inject_headers(plain, tc)
    for name in (HEADER_TRACEPARENT, HEADER_REQUEST_ID, HEADER_CLIENT_TRACE_ID):
        value = plain.get(name)
        if value and name not in request.headers:
            request.headers[name] = value


def inject_active_language_query_sync(request: httpx.Request) -> None:
    """Sync variant of `inject_active_language_query` for `httpx.Client`.

    Async hooks registered on a sync client return un-awaited coroutines
    and emit `RuntimeWarning: coroutine ... was never awaited` while
    silently failing to stamp the param — same correctness bug, just
    with a noisier log line.
    """
    _stamp_active_language(request)


def inject_active_support_language_query_sync(request: httpx.Request) -> None:
    """Sync variant of `inject_active_support_language_query` for
    `httpx.Client`. Sweep SSSS-C: required because some engine
    background workers use sync httpx clients and the async hook would
    silently no-op on them. Mirror of `inject_active_language_query_sync`.
    """
    _stamp_active_support_language(request)


def inject_trace_headers_sync(request: httpx.Request) -> None:
    """Sync variant of `inject_trace_headers` for `httpx.Client`."""
    _stamp_trace_headers(request)


__all__ = [
    "LEARNING_LANGUAGE_QUERY_PARAM",
    "LEARNING_LANGUAGE_HEADER",
    "SUPPORT_LANGUAGE_QUERY_PARAM",
    "SUPPORT_LANGUAGE_HEADER",
    "LANGUAGE_ATTRIBUTE",
    "inject_active_language_query",
    "inject_active_language_query_sync",
    "inject_active_support_language_query",
    "inject_active_support_language_query_sync",
    "inject_trace_headers",
    "inject_trace_headers_sync",
]
