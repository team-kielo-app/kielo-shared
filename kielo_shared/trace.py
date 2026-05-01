"""TraceContext primitives shared across Python Kielo services.

Mirrors ``kielo-shared/observe/trace.go`` (Go) and exposes a single
process-wide contextvar so any publisher in any Python service can
forward the current trace through Pub/Sub message attributes via
``kielo_shared.pubsub_utils.event_attributes``.

This module is intentionally minimal: services that own request-lifecycle
plumbing (FastAPI middleware, logging filters, httpx hooks) build on
top of these primitives but the primitives themselves have no FastAPI
or httpx dependency so they stay importable from any context.
"""
from __future__ import annotations

import contextvars
import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, MutableMapping, Optional


HEADER_TRACEPARENT = "traceparent"
HEADER_REQUEST_ID = "x-request-id"
HEADER_CLIENT_TRACE_ID = "x-client-trace-id"

ATTR_TRACE_ID = "trace_id"
ATTR_SPAN_ID = "span_id"
ATTR_PARENT_SPAN_ID = "parent_span_id"
ATTR_REQUEST_ID = "request_id"

_TRACEPARENT_RE = re.compile(
    r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$"
)
_HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
_ZERO_TRACE = "0" * 32
_ZERO_SPAN = "0" * 16


@dataclass
class TraceContext:
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str = ""
    request_id: str = ""
    flags: int = 0x01

    def is_zero(self) -> bool:
        return not self.trace_id

    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{self.flags:02x}"


def _random_hex(n_bytes: int) -> str:
    return secrets.token_hex(n_bytes)


def generate_request_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{ts}-{_random_hex(2)}"


def new_trace_context() -> TraceContext:
    return TraceContext(
        trace_id=_random_hex(16),
        span_id=_random_hex(8),
        request_id=generate_request_id(),
        flags=0x01,
    )


def child_span(parent: TraceContext) -> TraceContext:
    return TraceContext(
        trace_id=parent.trace_id,
        span_id=_random_hex(8),
        parent_span_id=parent.span_id,
        request_id=parent.request_id,
        flags=parent.flags,
    )


def parse_traceparent(value: str) -> Optional[TraceContext]:
    s = value.strip().lower()
    m = _TRACEPARENT_RE.match(s)
    if not m:
        return None
    version, trace_id, span_id, flags_hex = m.groups()
    if version == "ff":
        return None
    if trace_id == _ZERO_TRACE or span_id == _ZERO_SPAN:
        return None
    try:
        flags = int(flags_hex, 16)
    except ValueError:
        return None
    return TraceContext(trace_id=trace_id, span_id=span_id, flags=flags)


def format_traceparent(tc: TraceContext) -> str:
    return tc.traceparent()


def _normalize_to_trace_id(s: str) -> str:
    lower = s.strip().lower()
    if _HEX32_RE.match(lower):
        return lower
    digest = hashlib.sha256(s.encode("utf-8")).digest()
    return digest[:16].hex()


def from_headers(headers) -> TraceContext:
    tc: Optional[TraceContext] = None

    tp = headers.get(HEADER_TRACEPARENT)
    if tp:
        tc = parse_traceparent(tp)

    if tc is None or tc.is_zero():
        client_trace = headers.get(HEADER_CLIENT_TRACE_ID)
        if client_trace:
            tc = TraceContext(
                trace_id=_normalize_to_trace_id(client_trace),
                span_id=_random_hex(8),
                flags=0x01,
            )

    if tc is None or tc.is_zero():
        tc = new_trace_context()

    req_id = headers.get(HEADER_REQUEST_ID)
    if req_id:
        tc.request_id = req_id
    elif not tc.request_id:
        tc.request_id = generate_request_id()

    return tc


def inject_headers(headers: dict, tc: TraceContext) -> None:
    if tc.is_zero():
        return
    headers[HEADER_TRACEPARENT] = tc.traceparent()
    if tc.request_id:
        headers[HEADER_REQUEST_ID] = tc.request_id
    headers[HEADER_CLIENT_TRACE_ID] = tc.trace_id


_current: contextvars.ContextVar[TraceContext] = contextvars.ContextVar(
    "kielo_trace_context", default=TraceContext()
)


def current_trace_context() -> TraceContext:
    return _current.get()


def set_current_trace_context(tc: TraceContext) -> contextvars.Token:
    return _current.set(tc)


def reset_current_trace_context(token: contextvars.Token) -> None:
    _current.reset(token)


def inject_trace_attributes(
    attrs: MutableMapping[str, str],
    tc: Optional[TraceContext] = None,
) -> None:
    if tc is None:
        tc = current_trace_context()
    if tc is None or tc.is_zero():
        return
    attrs[ATTR_TRACE_ID] = tc.trace_id
    if tc.span_id:
        attrs[ATTR_SPAN_ID] = tc.span_id
    if tc.parent_span_id:
        attrs[ATTR_PARENT_SPAN_ID] = tc.parent_span_id
    if tc.request_id:
        attrs[ATTR_REQUEST_ID] = tc.request_id


def extract_trace_attributes(attrs: Mapping[str, str]) -> Optional[TraceContext]:
    trace_id = attrs.get(ATTR_TRACE_ID)
    if not trace_id:
        return None
    publisher = TraceContext(
        trace_id=trace_id,
        span_id=attrs.get(ATTR_SPAN_ID, ""),
        request_id=attrs.get(ATTR_REQUEST_ID, ""),
    )
    return child_span(publisher)


__all__ = [
    "TraceContext",
    "HEADER_TRACEPARENT",
    "HEADER_REQUEST_ID",
    "HEADER_CLIENT_TRACE_ID",
    "ATTR_TRACE_ID",
    "ATTR_SPAN_ID",
    "ATTR_PARENT_SPAN_ID",
    "ATTR_REQUEST_ID",
    "generate_request_id",
    "new_trace_context",
    "child_span",
    "parse_traceparent",
    "format_traceparent",
    "from_headers",
    "inject_headers",
    "current_trace_context",
    "set_current_trace_context",
    "reset_current_trace_context",
    "inject_trace_attributes",
    "extract_trace_attributes",
]
