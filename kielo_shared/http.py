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

import asyncio
import os
import threading
import weakref
from typing import Any, Optional, Union

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

MAX_CONNECTIONS = 100
MAX_KEEPALIVE_CONNECTIONS = 20
KEEPALIVE_EXPIRY_SECONDS = 60.0
HTTP2_DISABLED_ENV = "KIELO_HTTP_DISABLE_HTTP2"


def connection_limits() -> httpx.Limits:
    """Pool limits for every client this module builds.

    httpx drops an idle connection after 5 s by default, which is shorter than
    the gap between two calls on a lightly loaded instance, so every call paid
    a fresh TCP + TLS handshake. 60 s keeps the connection warm across those
    gaps; httpcore still discards a connection the peer has already closed.
    """
    return httpx.Limits(
        max_connections=MAX_CONNECTIONS,
        max_keepalive_connections=MAX_KEEPALIVE_CONNECTIONS,
        keepalive_expiry=KEEPALIVE_EXPIRY_SECONDS,
    )


def http2_enabled() -> bool:
    """Whether new clients offer HTTP/2 (ALPN ``h2``, falling back to HTTP/1.1).

    Off when the ``h2`` package is not installed (a consumer that did not add
    ``httpx[http2]``) or when ``KIELO_HTTP_DISABLE_HTTP2`` is set, so a bad h2
    interaction can be switched off without a code change. A server that does
    not select ``h2`` during the TLS handshake is served over HTTP/1.1 by httpx
    itself; plain ``http://`` URLs always use HTTP/1.1.
    """
    if os.environ.get(HTTP2_DISABLED_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return False
    try:
        import h2  # noqa: F401
    except ImportError:
        return False
    return True


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


def _client_kwargs(
    *,
    base_url: str,
    api_key: Optional[str],
    timeout: _TimeoutLike,
    headers: Optional[dict[str, str]],
    transport: Any,
    follow_redirects: bool,
    sync: bool,
) -> dict[str, Any]:
    default_headers: dict[str, str] = {}
    if api_key:
        default_headers[INTERNAL_API_KEY_HEADER] = api_key
    if headers:
        default_headers.update(headers)
    return {
        "base_url": base_url,
        "timeout": timeout,
        "headers": default_headers,
        "transport": transport,
        "follow_redirects": follow_redirects,
        "limits": connection_limits(),
        "http2": http2_enabled(),
        "event_hooks": {"request": _request_hooks_for(api_key, sync=sync)},
    }


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
    return httpx.AsyncClient(
        **_client_kwargs(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            headers=headers,
            transport=transport,
            follow_redirects=follow_redirects,
            sync=False,
        )
    )


def _request_hooks_for(api_key: Optional[str], *, sync: bool) -> list:
    """Build the request-hook chain for the canonical httpx factories.

    Trace headers are registered for EVERY client (internal + external) —
    unknown headers are harmless to external hosts and keep callout latency
    attributable to the worker context.

    The active learning/support language QUERY PARAMS are registered ONLY for
    internal Kielo peers (``api_key`` set). For external callouts
    (``api_key is None``: OpenAI, GCS signed URLs, third-party CDNs) they MUST
    NOT be injected: they leak an internal routing param off-platform, and on a
    signed URL an extra query param invalidates the signature (403). Sweep
    SSSS-C registered them unconditionally; that broke the invariant for
    external URLs.
    """
    from kielo_shared.httpx_hooks import (
        inject_active_language_query,
        inject_active_language_query_sync,
        inject_active_support_language_query,
        inject_active_support_language_query_sync,
        inject_trace_headers,
        inject_trace_headers_sync,
    )

    hooks: list = []
    if api_key:
        if sync:
            hooks.append(inject_active_language_query_sync)
            hooks.append(inject_active_support_language_query_sync)
        else:
            hooks.append(inject_active_language_query)
            hooks.append(inject_active_support_language_query)
    hooks.append(inject_trace_headers_sync if sync else inject_trace_headers)
    return hooks


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
    return httpx.Client(
        **_client_kwargs(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            headers=headers,
            transport=transport,
            follow_redirects=follow_redirects,
            sync=True,
        )
    )


class _SharedAsyncClient(httpx.AsyncClient):
    async def __aenter__(self) -> "_SharedAsyncClient":
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        return None

    async def aclose(self) -> None:
        return None

    async def _close_pool(self) -> None:
        await super().aclose()


class _SharedSyncClient(httpx.Client):
    def __enter__(self) -> "_SharedSyncClient":
        return self

    def __exit__(self, *_exc: Any) -> None:
        return None

    def close(self) -> None:
        return None

    def _close_pool(self) -> None:
        super().close()


_shared_lock = threading.Lock()
_shared_async: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, dict[tuple[Any, ...], _SharedAsyncClient]
] = weakref.WeakKeyDictionary()
_shared_sync: dict[tuple[Any, ...], _SharedSyncClient] = {}


def _shared_key(
    base_url: str,
    api_key: Optional[str],
    timeout: _TimeoutLike,
    headers: Optional[dict[str, str]],
    follow_redirects: bool,
) -> tuple[Any, ...]:
    return (
        base_url,
        api_key or "",
        repr(timeout),
        tuple(sorted((headers or {}).items())),
        follow_redirects,
    )


def shared_internal_client_async(
    *,
    base_url: str = "",
    api_key: Optional[str] = None,
    timeout: _TimeoutLike = 10.0,
    headers: Optional[dict[str, str]] = None,
    follow_redirects: bool = False,
) -> httpx.AsyncClient:
    """Return the long-lived client for this event loop and configuration.

    Same hook chain, headers and limits as :func:`internal_client_async`, but
    the client is built once per (running loop, ``base_url``, ``api_key``,
    ``timeout``, ``headers``, ``follow_redirects``) and handed to every caller,
    so the TCP/TLS connection (one multiplexed connection under HTTP/2) is
    reused across calls instead of re-opened.

    ``aclose()`` and ``async with`` on the returned client are no-ops, so a
    caller that was written for a private client cannot close the pool under
    its neighbours; :func:`aclose_shared_internal_clients` closes the real pool
    at shutdown. Call it from a running loop: httpx binds a connection to the
    loop that opened it. Without a running loop the result is a private client,
    exactly what :func:`internal_client_async` returns.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return internal_client_async(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            headers=headers,
            follow_redirects=follow_redirects,
        )

    key = _shared_key(base_url, api_key, timeout, headers, follow_redirects)
    with _shared_lock:
        clients = _shared_async.setdefault(loop, {})
        client = clients.get(key)
        if client is None or client.is_closed:
            client = _SharedAsyncClient(
                **_client_kwargs(
                    base_url=base_url,
                    api_key=api_key,
                    timeout=timeout,
                    headers=headers,
                    transport=None,
                    follow_redirects=follow_redirects,
                    sync=False,
                )
            )
            clients[key] = client
        return client


def shared_internal_client_sync(
    *,
    base_url: str = "",
    api_key: Optional[str] = None,
    timeout: _TimeoutLike = 10.0,
    headers: Optional[dict[str, str]] = None,
    follow_redirects: bool = False,
) -> httpx.Client:
    """Sync sibling of :func:`shared_internal_client_async`, one per process.

    ``httpx.Client`` is thread-safe, so the key carries no loop. ``close()`` and
    ``with`` are no-ops; :func:`close_shared_internal_clients` closes the pool.
    """
    key = _shared_key(base_url, api_key, timeout, headers, follow_redirects)
    with _shared_lock:
        client = _shared_sync.get(key)
        if client is None or client.is_closed:
            client = _SharedSyncClient(
                **_client_kwargs(
                    base_url=base_url,
                    api_key=api_key,
                    timeout=timeout,
                    headers=headers,
                    transport=None,
                    follow_redirects=follow_redirects,
                    sync=True,
                )
            )
            _shared_sync[key] = client
        return client


async def aclose_shared_internal_clients() -> None:
    """Close the running loop's shared async clients (engine/worker shutdown)."""
    loop = asyncio.get_running_loop()
    with _shared_lock:
        clients = _shared_async.pop(loop, {})
    for client in clients.values():
        await client._close_pool()


def close_shared_internal_clients() -> None:
    """Close every shared sync client."""
    with _shared_lock:
        clients = list(_shared_sync.values())
        _shared_sync.clear()
    for client in clients:
        client._close_pool()


__all__ = [
    "INTERNAL_API_KEY_HEADER",
    "KEEPALIVE_EXPIRY_SECONDS",
    "MAX_CONNECTIONS",
    "MAX_KEEPALIVE_CONNECTIONS",
    "aclose_shared_internal_clients",
    "close_shared_internal_clients",
    "connection_limits",
    "http2_enabled",
    "internal_client_async",
    "internal_client_sync",
    "internal_headers",
    "shared_internal_client_async",
    "shared_internal_client_sync",
]
