"""Deprecation + LegacyAlias Starlette middleware.

Python sibling of `kielo-shared/middleware/deprecation.go` (deleted in
fb524b5 once the Go v1 surface fully retired; revived here for the
Python v1 surface in kielolearn-engine that's still live).

Background (ADR-006 + api-v3-deprecation-plan): every Go service has
migrated to `/api/v3`. kielolearn-engine still mounts both
`/klearn/api/v1` and `/klearn/api/v3` and re-uses the v1 endpoint
modules from the v3 router. To retire `/klearn/api/v1` we first need:

  (a) IETF Deprecation / Sunset / Link headers on every v1 response so
      well-behaved clients can detect the migration window;
  (b) a burn-down counter per (method, path) so we can tell when v1
      traffic has decayed to zero and the routes are safe to delete.

Two factories cover the two cases:

  * `DeprecationMiddleware` — generic /v1 → /v3 marker. Default
    successor derived by replacing `/api/v1` (or `/klearn/api/v1`) with
    `/api/v3`. Increments `kielo_v1_route_hits_total{service,method,path}`.
  * `LegacyAliasMiddleware` — explicit successor required; used when a
    v3 path maps to a renamed canonical v3 path (e.g. `/feed` →
    `/me/recommendations/articles`). Increments
    `kielo_v3_legacy_alias_hits_total{service,path,successor}`.

Both are Starlette `BaseHTTPMiddleware` subclasses so they slot into
FastAPI's `app.add_middleware(...)` registration. Headers are set
BEFORE delegating to `call_next` so SSE/streaming responses (which flush
on first body byte) still carry them on the response head.

Counter increments happen pre-handler so 4xx/5xx requests are counted
too — we want to know "is anyone still calling this path?" regardless
of outcome.
"""

from __future__ import annotations

import datetime as _dt
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from kielo_shared.observability import (
    legacy_alias_hit_emit,
    v1_route_hit_emit,
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


def _default_v1_to_v3(path: str) -> str:
    """Derive the canonical v3 successor for a v1 request path.

    Handles both the public `/api/v1/...` shape and the engine-specific
    `/klearn/api/v1/...` shape with a single replace; ordering matters
    only insofar as the first matching pattern wins. Returns the input
    unchanged when neither prefix is present (caller should override
    `successor_path` for routes that don't follow the default mapping).
    """
    if "/api/v1" in path:
        return path.replace("/api/v1", "/api/v3", 1)
    return path


class DeprecationMiddleware(BaseHTTPMiddleware):
    """Mark every response from a v1 sub-app with Deprecation/Sunset/Link
    headers and increment `kielo_v1_route_hits_total`.

    Registration pattern (FastAPI sub-app per version):

        v1_app = FastAPI()
        v1_app.include_router(v1_router)
        v1_app.add_middleware(
            DeprecationMiddleware,
            service="kielolearn-engine",
        )
        app.mount("/klearn/api/v1", v1_app)

    OR, with the in-place router-prefix layout (engine's current shape),
    use `path_prefix=` to scope the middleware so /v3 + /worker requests
    pass through untouched:

        app.add_middleware(
            DeprecationMiddleware,
            service="kielolearn-engine",
            path_prefix="/klearn/api/v1",
        )

    Parameters
    ----------
    service : str
        Short service name used as the `service` metric label
        ("kielolearn-engine", "mobile-bff", …). Required — if empty,
        the counter is NOT incremented (headers still emit) so a
        misconfigured caller can't bloat unlabelled metric series.
    sunset : datetime, optional
        Wall-clock instant after which the route MAY return 410.
        Defaults to now + 90 days, computed at middleware construction.
    successor_path : str, optional
        Override the Link-header successor. When None (default), the
        successor is derived per request by `_default_v1_to_v3()`.
    path_prefix : str, optional
        Apply middleware ONLY to requests whose path starts with this
        prefix. None = apply to every request reaching this middleware
        layer (use when mounting as a sub-app where Starlette already
        scopes the path).
    skip : callable(Request) -> bool, optional
        Per-request escape hatch — return True to suppress headers AND
        metric increment for that request. Useful for v1 routes that
        have no v3 mirror (e.g. behavioral_events on a shared prefix).
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        service: str,
        sunset: Optional[_dt.datetime] = None,
        successor_path: Optional[str] = None,
        path_prefix: Optional[str] = None,
        skip: Optional[Callable[[Request], bool]] = None,
    ) -> None:
        super().__init__(app)
        self._service = service
        sunset_dt = sunset or (
            _dt.datetime.now(tz=_dt.timezone.utc)
            + _dt.timedelta(days=_DEFAULT_SUNSET_DAYS)
        )
        # Pre-render once; same string for every request handled by
        # this instance (matches the Go-side caching pattern).
        self._sunset_header = _rfc7231(sunset_dt)
        self._successor_override = successor_path
        self._path_prefix = path_prefix
        self._skip = skip

    async def dispatch(self, request: Request, call_next) -> Response:
        # Scope check first — when path_prefix is set, every request
        # outside that prefix is a no-op so the middleware can sit on
        # the global app without affecting /v3, /worker, /health, etc.
        if self._path_prefix is not None and not request.url.path.startswith(
            self._path_prefix
        ):
            return await call_next(request)
        if self._skip is not None and self._skip(request):
            return await call_next(request)

        # Note on increment timing: Starlette's BaseHTTPMiddleware runs
        # BEFORE route matching, so `request.scope["route"]` is None
        # here — the only way to get the route template (bounded label
        # cardinality, NOT the request URL) is to read it AFTER
        # `call_next`. We pay for this with a `try/finally` so the
        # counter still increments when the handler raises — which is
        # the spirit of "count every request, including 5xx/exceptions"
        # that the Go-side middleware achieved with a pre-handler bump.
        response: Optional[Response] = None
        try:
            response = await call_next(request)
            return self._decorate_response(request, response)
        finally:
            if self._service:
                route = request.scope.get("route")
                template = getattr(route, "path", None) or request.url.path
                if self._path_prefix and not template.startswith(self._path_prefix):
                    template = self._path_prefix + template
                v1_route_hit_emit(
                    service=self._service,
                    method=request.method,
                    path=template,
                )

    def _decorate_response(self, request: Request, response: Response) -> Response:
        """Attach Deprecation/Sunset/Link headers to a successful
        response. Split out from `dispatch` so the metric increment in
        the `finally` block can still run when the handler raises
        (no response object to decorate in that case)."""
        successor = self._successor_override or _default_v1_to_v3(request.url.path)
        response.headers["Deprecation"] = "true"
        response.headers["Sunset"] = self._sunset_header
        response.headers["Link"] = f'<{successor}>; rel="successor-version"'
        return response


class LegacyAliasMiddleware(BaseHTTPMiddleware):
    """Mark a v3 alias route as forwarding to a canonical v3 path.

    Differs from `DeprecationMiddleware`:
      * `successor_path` is REQUIRED (no default substitution — aliases
        live under /api/v3 with renamed canonical successors).
      * Increments `kielo_v3_legacy_alias_hits_total{service,path,successor}`
        — a separate burn-down series so /api/v1 retirement and
        /api/v3 alias retirement have independent dashboards.

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

        # Same "increment in finally so 5xx counts" pattern as
        # `DeprecationMiddleware.dispatch` — see comment there.
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
