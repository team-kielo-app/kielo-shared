"""aiohttp middleware mirroring the httpx event hooks.

`kielo-web-ingest` uses ``aiohttp.ClientSession`` for outbound HTTP
because the project standardized on it long before ``httpx`` became
the de-facto choice. The existing :mod:`kielo_shared.httpx_hooks` only
fires for ``httpx`` clients; aiohttp callers silently miss trace and
learning-language propagation, which is the root cause of the
"web-ingest crawls never appear in trace search" complaint.

This module ports the same two hooks to aiohttp. Apply via
``aiohttp.TraceConfig`` — aiohttp's request-lifecycle plug-in surface —
which keeps the hook code out of the session constructor and lets
``kielo-web-ingest`` reuse its existing session-factory pattern.

Per ADR-006 §9.

Import side-effects: ``aiohttp`` is NOT a hard dependency of
``kielo-shared``. Importing this module without aiohttp installed
raises a clear ``ImportError``; do not import at package init.
"""

from __future__ import annotations

from typing import Any

try:
    import aiohttp
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "kielo_shared.aiohttp_hooks requires aiohttp. "
        "Add `aiohttp` to the consuming service's dependencies."
    ) from exc

from kielo_shared.http import INTERNAL_API_KEY_HEADER
from kielo_shared.trace import (
    HEADER_CLIENT_TRACE_ID,
    HEADER_REQUEST_ID,
    HEADER_TRACEPARENT,
    current_trace_context,
    inject_headers,
)


async def _on_request_start(
    session: aiohttp.ClientSession,
    trace_config_ctx: Any,
    params: aiohttp.TraceRequestStartParams,
) -> None:
    """aiohttp trace hook — stamps trace + learning-language headers on
    every outbound request.

    aiohttp's ``TraceRequestStartParams.headers`` is the mutable
    ``CIMultiDict`` that aiohttp will actually send on the wire, but
    ``params.url`` is a frozen attrs field. So unlike the httpx hooks —
    which can rewrite the URL to add ``?learning_language_code=...`` —
    the aiohttp hook stamps the language as the canonical
    ``X-Kielo-Learning-Language`` HEADER instead. Per ADR-006 §3 the
    header is the canonical source-of-truth on the wire; the query
    param is a lower-precedence mirror. All Kielo services that read
    learning-language from inbound calls accept both forms.
    """
    _stamp_active_language_aiohttp(params)
    _stamp_trace_headers_aiohttp(params)


def _stamp_active_language_aiohttp(
    params: aiohttp.TraceRequestStartParams,
) -> None:
    from kielo_shared.db_utils import get_active_language

    lang = get_active_language()
    if not lang:
        return
    # Canonical header per ADR-006 §3. Mirrors X-Kielo-Learning-Language
    # the mobile-bff sends to backend services and what other Kielo
    # services accept on inbound. Don't override if the caller set it
    # explicitly.
    if "X-Kielo-Learning-Language" not in params.headers:
        params.headers["X-Kielo-Learning-Language"] = lang


def _stamp_trace_headers_aiohttp(
    params: aiohttp.TraceRequestStartParams,
) -> None:
    tc = current_trace_context()
    if tc.is_zero():
        return

    headers: dict[str, str] = {}
    inject_headers(headers, tc)
    for name in (HEADER_TRACEPARENT, HEADER_REQUEST_ID, HEADER_CLIENT_TRACE_ID):
        value = headers.get(name)
        if value and name not in params.headers:
            params.headers[name] = value


def tracing_trace_config() -> aiohttp.TraceConfig:
    """Return an ``aiohttp.TraceConfig`` that stamps trace headers and
    the active learning-language query param on every outbound request.

    Register on every ``ClientSession`` constructor:

        session = aiohttp.ClientSession(
            trace_configs=[tracing_trace_config()],
        )

    Multiple TraceConfigs can co-exist; this one is composable with
    e.g. an OpenTelemetry trace config.
    """
    cfg = aiohttp.TraceConfig()
    cfg.on_request_start.append(_on_request_start)
    return cfg


def internal_session(
    *,
    api_key: str = "",
    base_headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> aiohttp.ClientSession:
    """Return an ``aiohttp.ClientSession`` wired for Kielo internal calls.

    The returned session:
      * Stamps ``X-Internal-API-Key`` on every request when ``api_key``
        is non-empty (via the session-level default headers).
      * Carries the trace + learning-language hook via the
        :func:`tracing_trace_config` ``TraceConfig``.

    Extra ``**kwargs`` are forwarded to ``aiohttp.ClientSession``; pass
    e.g. ``connector=...`` or ``timeout=...`` as needed.

    Note: aiohttp does not deep-merge session-level default headers
    with per-request headers — per-request always wins, which matches
    the "explicit override survives" semantics of the Go transport.
    """
    headers: dict[str, str] = {}
    if api_key:
        headers[INTERNAL_API_KEY_HEADER] = api_key
    if base_headers:
        headers.update(base_headers)

    trace_configs = list(kwargs.pop("trace_configs", []))
    trace_configs.append(tracing_trace_config())

    return aiohttp.ClientSession(
        headers=headers or None,
        trace_configs=trace_configs,
        **kwargs,
    )


__all__ = [
    "tracing_trace_config",
    "internal_session",
]
