"""LegacyAlias Starlette middleware (v3 alias retirement).

Python sibling of `kielo-shared/middleware/deprecation.go` (deleted in
fb524b5 once the Go v1 surface fully retired). This file used to also
host `DeprecationMiddleware` for the Python /klearn/api/v1 surface; it
was retired when kielolearn-engine deleted its v1 router (zero
remaining HTTP callers — see survey in commit message), leaving only
the v3-alias retirement infra here.

Background (ADR-006 + api-v3-deprecation-plan): every service has
migrated to `/api/v3`. Some v3 paths have renamed canonical successors
(e.g. `/feed` → `/me/recommendations/articles`); requests to the old
alias get tagged with IETF Deprecation/Sunset/Link headers and counted
toward a burn-down counter so we can see when traffic decays to zero
and the alias can be deleted.

  * `LegacyAliasMiddleware` — explicit successor required; tags renamed
    v3 routes. Increments
    `kielo_v3_legacy_alias_hits_total{service,path,successor}`.

`BaseHTTPMiddleware` subclass so it slots into FastAPI's
`app.add_middleware(...)` registration. Headers are set BEFORE
delegating to `call_next` so SSE/streaming responses (which flush on
first body byte) still carry them on the response head. Counter
increments happen pre-handler so 4xx/5xx requests are counted too —
we want to know "is anyone still calling this path?" regardless of
outcome.
"""

from __future__ import annotations

import datetime as _dt
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from kielo_shared.observability import (
    legacy_alias_hit_emit,
)


# Default sunset horizon — matches the deleted Go `Deprecation` default
# (90 days from process start). Computed once per middleware instance at
# construction time so the header string is stable across requests for
# the lifetime of the process, but distinct between deploys (which is
# what we want for rolling cutover).
_DEFAULT_SUNSET_DAYS = 90


def _rfc7231(date: _dt.datetime) -> str:
    """Format a datetime as RFC 7231 IMF-fixdate (HTTP date format).

    Always emits in UTC. RFC 8594 requires the Sunset header to use this
    exact format ("Sun, 06 Nov 1994 08:49:37 GMT"). Python's strftime is
    locale-sensitive for `%a` / `%b`, so we hand-roll the day/month
    names to stay locale-independent.
    """
    utc = date.astimezone(_dt.timezone.utc)
    days = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    months = (
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    )
    return (
        f"{days[utc.weekday()]}, {utc.day:02d} {months[utc.month - 1]} "
        f"{utc.year:04d} {utc.hour:02d}:{utc.minute:02d}:{utc.second:02d} GMT"
    )


class LegacyAliasMiddleware(BaseHTTPMiddleware):
    """Mark a v3 alias route as forwarding to a canonical v3 path.

    `successor_path` is required because aliases already live under
    /api/v3 with renamed canonical successors. Hits increment
    `kielo_v3_legacy_alias_hits_total{service,path,successor}`.

    Registration pattern: mount once per alias path with `path_prefix`
    scoped to that specific path so only matching requests are tagged.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        service: str,
        successor_path: str,
        sunset: Optional[_dt.datetime] = None,
        path_prefix: Optional[str] = None,
    ) -> None:
        super().__init__(app)
        if not service or not successor_path:
            # Misconfigured callers get a soft no-op so a typo in
            # registration doesn't take down the whole service. The
            # missing-arg case is loud enough at code review.
            self._noop = True
            self._service = ""
            self._successor_path = ""
            self._sunset_header = ""
            self._path_prefix = None
            self._link_header = ""
            return
        self._noop = False
        self._service = service
        self._successor_path = successor_path
        sunset_dt = sunset or (
            _dt.datetime.now(tz=_dt.timezone.utc)
            + _dt.timedelta(days=_DEFAULT_SUNSET_DAYS)
        )
        self._sunset_header = _rfc7231(sunset_dt)
        self._link_header = f'<{successor_path}>; rel="successor-version"'
        self._path_prefix = path_prefix

    async def dispatch(self, request: Request, call_next) -> Response:
        if self._noop:
            return await call_next(request)
        if self._path_prefix is not None and not request.url.path.startswith(
            self._path_prefix
        ):
            return await call_next(request)

        # Increment in finally so 5xx paths count too; the burn-down
        # signal is "is anyone still calling this alias?", regardless
        # of outcome.
        try:
            response = await call_next(request)
            response.headers["Deprecation"] = "true"
            response.headers["Sunset"] = self._sunset_header
            response.headers["Link"] = self._link_header
            return response
        finally:
            route = request.scope.get("route")
            template = getattr(route, "path", None) or request.url.path
            if self._path_prefix and not template.startswith(self._path_prefix):
                template = self._path_prefix + template
            legacy_alias_hit_emit(
                service=self._service,
                path=template,
                successor=self._successor_path,
            )
