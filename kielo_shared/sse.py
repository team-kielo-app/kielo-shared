"""Shared Server-Sent Events helpers for Python Kielo services.

Mirrors ``kielo-shared/sse`` (Go): canonical event/data wire format,
the four headers EventSource needs over an nginx ingress
(``Content-Type``, ``Cache-Control: no-cache``, ``Connection: keep-alive``,
``X-Accel-Buffering: no``), heartbeat-as-comment convention, and
disconnect handling.

Why X-Accel-Buffering: no — nginx (and Cloud Run's frontend proxy)
buffer responses by default. Without that header, SSE frames sit in
nginx's output buffer until enough bytes accumulate, which can defer
events for seconds. EventSource clients then time out or appear stuck.

Why heartbeats are SSE comments (``: heartbeat\\n\\n``) and not events:
- comments are 1/4 the size of a fully-named event with empty data
- EventSource silently drops them; no listener fires, no allocation
- matches Go ``sse.Writer.SendComment()`` so producers/consumers across
  the Python/Go boundary speak the same dialect
- nginx, Cloud Run, and CDNs treat comments as proper keepalive frames

Producers yield mappings like::

    {"event": "persisted", "payload": {...}}     # named event
    {"id": "42-0", "event": "...", "payload": ...} # named event with id
    {"comment": "heartbeat"}                      # SSE comment
    {"event": "keepalive", "payload": {}}         # alias — auto-translated
                                                   # to {"comment": "heartbeat"}

The ``keepalive`` alias keeps existing producers (e.g. kielolearn-engine's
generation_progress_service) working unchanged while pushing them onto
the canonical wire format.

Usage::

    @router.get("/jobs/{job_id}/stream")
    async def stream_job(request: Request, job_id: uuid.UUID):
        async def producer() -> AsyncIterator[dict]:
            async for event in generation_progress_service.stream_job_events(job_id):
                yield event

        return sse_response(
            request=request,
            events=producer(),
            terminal_events={"persisted", "failed"},
        )
"""
from __future__ import annotations

import json
from typing import AbstractSet, Any, AsyncIterator, Awaitable, Callable, Mapping, Optional


SSE_HEADERS: dict = {
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}

# Default comment payload when a producer yields {"event": "keepalive"} without
# a custom comment. Matches ``kielo-shared/sse`` (Go) ``SendComment`` heartbeats.
DEFAULT_HEARTBEAT_COMMENT = "heartbeat"


def format_event(event_id: str, event_name: str, payload: Any) -> str:
    """Encode one named SSE event frame. ``id:`` is omitted when empty."""
    parts: list[str] = []
    if event_id:
        parts.append(f"id: {event_id}")
    parts.append(f"event: {event_name}")
    parts.append(f"data: {json.dumps(payload, ensure_ascii=False)}")
    return "\n".join(parts) + "\n\n"


def format_comment(comment: str = DEFAULT_HEARTBEAT_COMMENT) -> str:
    """Encode an SSE comment frame.

    EventSource clients silently discard comments; they exist purely to
    keep the connection warm through proxies/CDNs.
    """
    safe = comment.replace("\n", " ").replace("\r", " ")
    return f": {safe}\n\n"


def _coerce_event_to_frame(event: Mapping[str, Any]) -> str:
    """Translate a producer-yielded event into the SSE wire format.

    - ``{"comment": "..."}`` → ``: ...\\n\\n``
    - ``{"event": "keepalive", ...}`` (legacy alias) → comment frame
    - everything else → ``id:`` + ``event:`` + ``data:`` frame
    """
    comment = event.get("comment")
    if comment:
        return format_comment(str(comment))
    event_name = str(event.get("event", "") or "")
    if event_name == "keepalive":
        return format_comment(DEFAULT_HEARTBEAT_COMMENT)
    return format_event(
        event_id=str(event.get("id", "") or ""),
        event_name=event_name,
        payload=event.get("payload"),
    )


async def _format_stream(
    request,
    events: AsyncIterator[Mapping[str, Any]],
    terminal_events: AbstractSet[str],
    payload_transform: Optional[
        Callable[[Mapping[str, Any]], Awaitable[Any]]
    ] = None,
) -> AsyncIterator[str]:
    async for event in events:
        if hasattr(request, "is_disconnected"):
            if await request.is_disconnected():
                break
        # Non-keepalive named events go through the optional transform.
        if (
            payload_transform is not None
            and not event.get("comment")
            and event.get("event") not in {"", "keepalive"}
        ):
            transformed = await payload_transform(event)
            event = {**event, "payload": transformed}
        yield _coerce_event_to_frame(event)
        if event.get("event") in terminal_events:
            break


def sse_response(
    *,
    request,
    events: AsyncIterator[Mapping[str, Any]],
    terminal_events: AbstractSet[str] = frozenset(),
    payload_transform: Optional[
        Callable[[Mapping[str, Any]], Awaitable[Any]]
    ] = None,
):
    """Build a canonical FastAPI/Starlette SSE response.

    ``events`` yields ``{"event": str, "payload": any, "id": str?}`` mappings
    or ``{"comment": str}`` for comment frames. The generator stops on
    client disconnect or after a terminal event.

    ``payload_transform`` is an optional async hook that receives the
    raw event mapping and returns the payload to serialize (used by
    handlers that localize event content per-request).

    Importing FastAPI is deferred so this module stays usable from
    services that ship without FastAPI (admin scripts, tests).
    """
    from fastapi.responses import StreamingResponse  # local import

    return StreamingResponse(
        _format_stream(
            request=request,
            events=events,
            terminal_events=terminal_events,
            payload_transform=payload_transform,
        ),
        media_type="text/event-stream",
        headers=SSE_HEADERS,
    )


__all__ = [
    "SSE_HEADERS",
    "DEFAULT_HEARTBEAT_COMMENT",
    "format_event",
    "format_comment",
    "sse_response",
]
