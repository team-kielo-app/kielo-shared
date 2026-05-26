"""kielo_shared.http: convenience helpers for service-to-service HTTP.

Per ADR-006 §9 + §8, every outbound HTTP call between Kielo Python
services must carry:

  * ``Traceparent`` / ``X-Request-Id`` / ``X-Client-Trace-Id`` — trace
    correlation headers populated from the active TraceContext
    contextvar.
  * ``X-Internal-API-Key`` — shared service-to-service secret.
  * The active learning language as a ``learning_language_code`` query
    parameter (handled by the existing httpx event hook
    :func:`kielo_shared.httpx_hooks.inject_active_language_query`).

Two surfaces:

  * :func:`internal_headers` — returns a header dict that callers can
    splat onto any one-off ``requests`` / ``httpx`` / ``urllib`` call.
    Use when constructing a long-lived client is overkill (ad-hoc
    background tasks, CLI tools).

  * :func:`internal_client_async` — returns a fully configured
    ``httpx.AsyncClient`` with both event hooks registered and a
    default ``X-Internal-API-Key`` header. The preferred shape for
    services that talk to Kielo peers repeatedly.

The constants here intentionally re-export :data:`INTERNAL_API_KEY_HEADER`
so callers don't have to remember the spelling — historically
``X-API-Key`` and ``X-Internal-API-Key`` were both in use; the latter
is canonical per ADR-006 §2.
"""

from __future__ import annotations

from typing import Optional, Union

import httpx

from kielo_shared.trace import (
    HEADER_CLIENT_TRACE_ID,
    HEADER_REQUEST_ID,
    HEADER_TRACEPARENT,
    current_trace_context,
    inject_headers,
)

# httpx accepts either a bare float (applied to all phases) or a fully
# configured httpx.Timeout for fine-grained control (connect/read/
# write/pool). We surface both so callers don't have to choose between
# the canonical hook-wired factory and per-phase timeout tuning.
_TimeoutLike = Union[float, httpx.Timeout]


# Canonical service-to-service auth header. Mirrors
# middleware.InternalAPIKeyHeader on the Go side. The frontend admin UI
# uses a SEPARATE ``X-API-Key`` for its own admin secret; conflating
# the two is the long-standing source of cross-service 401s.
INTERNAL_API_KEY_HEADER = "X-Internal-API-Key"


def internal_headers(
    api_key: Optional[str] = None,
    extra: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Return a header dict suitable for an outbound call to a Kielo peer.

    The returned dict includes:
      * ``X-Internal-API-Key`` (when ``api_key`` is non-empty)
      * ``Traceparent`` / ``X-Request-Id`` / ``X-Client-Trace-Id``
        populated from the active TraceContext contextvar; absent when
        the caller has no trace context (e.g. CLI tools, module-load).

    ``extra`` is merged last so callers can override or supplement
    (typical use: ``Content-Type: application/json``).

    The function does NOT stamp the learning-language query param —
    that lives on the URL, not in headers. Use the httpx event hook
    :func:`kielo_shared.httpx_hooks.inject_active_language_query` or
    pass the param explicitly when building the URL.
    """
    headers: dict[str, str] = {}
    if api_key:
        headers[INTERNAL_API_KEY_HEADER] = api_key

    tc = current_trace_context()
    if not tc.is_zero():
        trace_headers: dict[str, str] = {}
        inject_headers(trace_headers, tc)
        for name in (HEADER_TRACEPARENT, HEADER_REQUEST_ID, HEADER_CLIENT_TRACE_ID):
            value = trace_headers.get(name)
            if value:
                # Capitalize for HTTP/1.1 wire convention; httpx and
                # requests normalize anyway, but writing the canonical
                # case keeps direct ``urllib`` users honest.
                headers[
                    name.title()
                    if name == HEADER_TRACEPARENT
                    else _canonical_case(name)
                ] = value

    if extra:
        headers.update(extra)
    return headers


def _canonical_case(header_name: str) -> str:
    # Convert "x-request-id" → "X-Request-Id".
    return "-".join(part.capitalize() for part in header_name.split("-"))


def internal_client_async(
    *,
    base_url: str = "",
    api_key: Optional[str] = None,
    timeout: _TimeoutLike = 10.0,
    headers: Optional[dict[str, str]] = None,
    transport: Optional[httpx.AsyncBaseTransport] = None,
    follow_redirects: bool = False,
) -> httpx.AsyncClient:
    """Return an ``httpx.AsyncClient`` wired with the canonical hook chain.

    Per ADR-006 §3/§9 this is the single factory for **all** outbound
    httpx clients in Python services — internal Kielo peers and
    external endpoints alike. The simple invariant is:
    "every outbound httpx client carries the shared event hooks".

    The returned client:

      * Registers the two shared event hooks
        (:func:`inject_active_language_query` and
        :func:`inject_trace_headers`) so every request carries trace
        correlation headers (W3C Traceparent + X-Request-Id +
        X-Client-Trace-Id) and the active learning language (both
        ``learning_language_code`` query param and
        ``X-Kielo-Learning-Language`` header).
      * Stamps ``X-Internal-API-Key`` on every request when ``api_key``
        is non-empty (set as a default header so per-call overrides
        still work). Pass ``api_key=None`` for external callouts
        (OpenAI, GCS signed URLs, third-party CDNs).

    Use in place of ``httpx.AsyncClient(...)``. For one-off calls,
    :func:`internal_headers` + a vanilla client may be simpler.

    ``headers`` is merged into the default header set; pass ``None`` to
    use only the canonical defaults.
    """
    from kielo_shared.httpx_hooks import (
        inject_active_language_query,
        inject_trace_headers,
    )

    default_headers: dict[str, str] = {}
    if api_key:
        default_headers[INTERNAL_API_KEY_HEADER] = api_key
    if headers:
        default_headers.update(headers)

    return httpx.AsyncClient(
        base_url=base_url,
        timeout=timeout,
        headers=default_headers,
        transport=transport,
        follow_redirects=follow_redirects,
        event_hooks={
            "request": [
                inject_active_language_query,
                inject_trace_headers,
            ],
        },
    )


def internal_client_sync(
    *,
    base_url: str = "",
    api_key: Optional[str] = None,
    timeout: _TimeoutLike = 10.0,
    headers: Optional[dict[str, str]] = None,
    transport: Optional[httpx.BaseTransport] = None,
    follow_redirects: bool = False,
) -> httpx.Client:
    """Sync variant of :func:`internal_client_async`.

    Same ADR-006 invariant: this is the canonical factory for every
    sync outbound httpx client (internal peers and external endpoints).
    New code should prefer the async variant; the sync sibling exists
    for callers stuck in a sync code path (CLI tools, legacy worker
    threads).
    """
    from kielo_shared.httpx_hooks import (
        inject_active_language_query_sync,
        inject_trace_headers_sync,
    )

    default_headers: dict[str, str] = {}
    if api_key:
        default_headers[INTERNAL_API_KEY_HEADER] = api_key
    if headers:
        default_headers.update(headers)

    return httpx.Client(
        base_url=base_url,
        timeout=timeout,
        headers=default_headers,
        transport=transport,
        follow_redirects=follow_redirects,
        event_hooks={
            "request": [
                inject_active_language_query_sync,
                inject_trace_headers_sync,
            ],
        },
    )


__all__ = [
    "INTERNAL_API_KEY_HEADER",
    "internal_headers",
    "internal_client_async",
    "internal_client_sync",
]
