"""Learner timezone offset for Python user-action emitters.

Python counterpart of Go ``timeutil.WithTimezoneOffsetMinutes`` +
``middleware.TimezoneOffset`` + the ``events.HTTPEmitter`` stamp: the kielo-events
envelope carries ``context.tz_offset_minutes`` (UTC offset of the learner, in
minutes) so per-user daily rollovers (streaks, limits) use the learner's day.

Two sources, in order:

1. The request: ``TimezoneOffsetMiddleware`` copies ``X-Timezone-Offset-Minutes``
   (legacy alias ``X-Timezone-Offset``) into a context variable for the request.
2. The learner's stored offset (``users.users.timezone_offset_minutes``) via
   ``lookup_stored_timezone_offset``, for emitters with no request (workers).

``stamp_timezone_offset`` adds the key to an envelope context, never replacing a
value the caller set and never mutating the caller's dict. No offset known ->
the context is returned unchanged (optional, backward compatible). An explicit
UTC (0) is stamped.
"""

from __future__ import annotations

import contextvars
from typing import Any, Mapping, MutableMapping, Optional

TIMEZONE_OFFSET_HEADER = "X-Timezone-Offset-Minutes"
LEGACY_TIMEZONE_OFFSET_HEADER = "X-Timezone-Offset"
CONTEXT_TZ_OFFSET_KEY = "tz_offset_minutes"

MIN_TIMEZONE_OFFSET_MINUTES = -14 * 60
MAX_TIMEZONE_OFFSET_MINUTES = 14 * 60

_request_offset: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar(
    "kielo_request_tz_offset_minutes", default=None
)


def parse_timezone_offset_minutes(raw: Any) -> Optional[int]:
    """Validated offset in minutes, or None for empty/malformed/out-of-range."""
    if raw is None or isinstance(raw, bool):
        return None
    try:
        offset = int(str(raw).strip())
    except ValueError:
        return None
    if offset < MIN_TIMEZONE_OFFSET_MINUTES or offset > MAX_TIMEZONE_OFFSET_MINUTES:
        return None
    return offset


def set_request_timezone_offset(
    offset: Optional[int],
) -> contextvars.Token[Optional[int]]:
    return _request_offset.set(parse_timezone_offset_minutes(offset))


def reset_request_timezone_offset(token: contextvars.Token[Optional[int]]) -> None:
    _request_offset.reset(token)


def get_request_timezone_offset() -> Optional[int]:
    return _request_offset.get()


def stamp_timezone_offset(
    context: Optional[Mapping[str, Any]], offset: Optional[int] = None
) -> Optional[dict[str, Any]]:
    """Return ``context`` with ``tz_offset_minutes`` added when known.

    ``offset`` wins over the request's; an existing key in ``context`` always
    wins. Returns None only when there is nothing to carry.
    """
    if context is not None and CONTEXT_TZ_OFFSET_KEY in context:
        return dict(context)
    resolved = parse_timezone_offset_minutes(offset)
    if resolved is None:
        resolved = get_request_timezone_offset()
    if resolved is None:
        return dict(context) if context else None
    stamped: MutableMapping[str, Any] = dict(context) if context else {}
    stamped[CONTEXT_TZ_OFFSET_KEY] = resolved
    return dict(stamped)


class TimezoneOffsetMiddleware:
    """Pure ASGI middleware: bind the caller's offset header to the request.

    Pure ASGI (not BaseHTTPMiddleware) so the context variable is set in the
    task that runs the endpoint. A missing or invalid header leaves it unset.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        wanted = {
            TIMEZONE_OFFSET_HEADER.lower().encode(): 0,
            LEGACY_TIMEZONE_OFFSET_HEADER.lower().encode(): 1,
        }
        found: list[Optional[int]] = [None, None]
        for name, value in scope.get("headers", []):
            slot = wanted.get(name.lower())
            if slot is not None and found[slot] is None:
                found[slot] = parse_timezone_offset_minutes(value.decode("latin-1"))
        offset = found[0] if found[0] is not None else found[1]
        token = _request_offset.set(offset)
        try:
            await self.app(scope, receive, send)
        finally:
            _request_offset.reset(token)


async def lookup_stored_timezone_offset(
    session_factory: Any, user_id: Any
) -> Optional[int]:
    """The learner's stored offset (``users.users.timezone_offset_minutes``).

    ``session_factory()`` must yield an async context-managed SQLAlchemy
    session. Best effort: any failure, missing row or NULL returns None.
    """
    if session_factory is None or not user_id:
        return None
    try:
        from sqlalchemy import text

        async with session_factory() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT timezone_offset_minutes FROM users.users WHERE id = :uid"
                    ),
                    {"uid": str(user_id)},
                )
            ).first()
    except Exception:  # silent-degrade-allow: the offset is optional context; the event still ships without it.
        return None
    if row is None:
        return None
    return parse_timezone_offset_minutes(row[0])
