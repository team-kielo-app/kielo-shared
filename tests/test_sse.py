"""Tests for kielo_shared.sse — wire-format pinning.

The SSE wire format is rigid: EventSource parses by textual prefix.
Dropping ``\\n\\n``, swapping ``event:`` for ``event ``, or missing
``data:`` silently breaks every real-time progress UI. These tests pin
the bytes so a regression is loud.

Mirrors ``kielo-shared/sse/writer_test.go`` (Go).
"""
from __future__ import annotations

import asyncio
import json

import pytest

from kielo_shared.sse import (
    SSE_HEADERS,
    _coerce_event_to_frame,
    _format_stream,
    format_comment,
    format_event,
)


def test_sse_headers_include_x_accel_buffering():
    """X-Accel-Buffering: no is what stops nginx/Cloud Run from
    buffering SSE frames into multi-second batches."""
    assert SSE_HEADERS["X-Accel-Buffering"] == "no"
    assert SSE_HEADERS["Cache-Control"] == "no-cache"
    assert SSE_HEADERS["Connection"] == "keep-alive"


def test_format_event_with_id():
    out = format_event("42-0", "persisted", {"job_id": "abc", "ok": True})
    assert out == 'id: 42-0\nevent: persisted\ndata: {"job_id": "abc", "ok": true}\n\n'


def test_format_event_without_id_omits_id_line():
    """``id:`` is omitted when empty — EventSource only updates Last-Event-ID
    when an id is actually present, so emitting ``id:\\n`` would clear it."""
    out = format_event("", "progress", {"pct": 42})
    assert "id:" not in out
    assert out == 'event: progress\ndata: {"pct": 42}\n\n'


def test_format_event_serializes_unicode_natively():
    """ensure_ascii=False keeps Finnish/Swedish payloads readable on the wire."""
    out = format_event("", "preview", {"title": "Saa ja vuodenajat"})
    assert "Saa ja vuodenajat" in out
    assert "\\u" not in out


def test_format_comment_default_heartbeat():
    """Comments are tiny, EventSource ignores them — perfect for proxies."""
    assert format_comment() == ": heartbeat\n\n"


def test_format_comment_strips_newlines():
    """A newline in a comment would close the frame early and inject an empty
    event into the stream — clip them defensively."""
    assert format_comment("foo\nbar\rbaz") == ": foo bar baz\n\n"


def test_coerce_translates_legacy_keepalive_event_to_comment():
    """Producers that still yield {"event": "keepalive"} should land on
    the canonical comment-frame wire format without code changes."""
    frame = _coerce_event_to_frame({"event": "keepalive", "payload": {}})
    assert frame == ": heartbeat\n\n"


def test_coerce_explicit_comment_uses_provided_text():
    frame = _coerce_event_to_frame({"comment": "still here"})
    assert frame == ": still here\n\n"


def test_coerce_named_event_passes_through():
    frame = _coerce_event_to_frame(
        {"id": "1", "event": "ready", "payload": {"x": 1}}
    )
    assert frame == 'id: 1\nevent: ready\ndata: {"x": 1}\n\n'


class _StubRequest:
    """Minimal FastAPI Request stand-in."""

    def __init__(self, disconnect_after: int | None = None):
        self._calls = 0
        self._disconnect_after = disconnect_after

    async def is_disconnected(self) -> bool:
        if self._disconnect_after is None:
            return False
        result = self._calls >= self._disconnect_after
        self._calls += 1
        return result


async def _collect(generator):
    out: list[str] = []
    async for chunk in generator:
        out.append(chunk)
    return out


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.mark.asyncio
async def test_format_stream_terminates_on_terminal_event():
    async def events():
        yield {"event": "progress", "payload": {"pct": 10}}
        yield {"event": "persisted", "payload": {"ok": True}}
        yield {"event": "after_terminal", "payload": {"should_not": "ship"}}

    out = await _collect(
        _format_stream(
            request=_StubRequest(),
            events=events(),
            terminal_events={"persisted"},
        )
    )
    assert len(out) == 2
    assert "after_terminal" not in "".join(out)


@pytest.mark.asyncio
async def test_format_stream_stops_on_disconnect():
    async def events():
        for i in range(5):
            yield {"event": "progress", "payload": {"i": i}}

    out = await _collect(
        _format_stream(
            request=_StubRequest(disconnect_after=2),
            events=events(),
            terminal_events=set(),
        )
    )
    assert len(out) <= 3


@pytest.mark.asyncio
async def test_format_stream_applies_payload_transform_to_named_events_only():
    """The transform should NOT run on heartbeat comments — they have no
    payload to mutate."""

    async def events():
        yield {"event": "preview", "payload": {"title": "raw"}}
        yield {"event": "keepalive", "payload": {}}
        yield {"event": "preview", "payload": {"title": "raw2"}}

    transform_calls = 0

    async def transform(event):
        nonlocal transform_calls
        transform_calls += 1
        return {**event["payload"], "title": event["payload"]["title"].upper()}

    out = await _collect(
        _format_stream(
            request=_StubRequest(),
            events=events(),
            terminal_events=set(),
            payload_transform=transform,
        )
    )
    assert transform_calls == 2  # not called for keepalive
    assert any("RAW" in chunk for chunk in out)
    assert any(chunk == ": heartbeat\n\n" for chunk in out)


@pytest.mark.asyncio
async def test_format_stream_emits_canonical_double_newline_terminator():
    """SSE frames MUST end with ``\\n\\n``. A single newline merges adjacent
    frames silently and EventSource just stops dispatching."""

    async def events():
        yield {"event": "ping", "payload": {}}
        yield {"comment": "tick"}

    out = await _collect(
        _format_stream(
            request=_StubRequest(),
            events=events(),
            terminal_events=set(),
        )
    )
    for chunk in out:
        assert chunk.endswith("\n\n")
