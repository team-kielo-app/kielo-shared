"""Tests for kielo_shared.middleware.support_locale_overrides.

Covers the wire-up contract:
  * On request entry the middleware resolves the locale via the
    caller-supplied resolver and prefetches overrides for it.
  * The prefetched map is exposed to the endpoint via the contextvar
    in `support_locale_overrides`.
  * English / empty locales skip the prefetch (no DB hit).
  * Resolver errors and prefetch errors fail-open (request continues
    with no overrides applied).
"""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from kielo_shared.localization.support_locale_overrides import get_override
from kielo_shared.middleware.support_locale_overrides import (
    SupportLocaleOverridesMiddleware,
)


def _sv(english: str) -> str:
    return hashlib.sha256(english.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Test fixtures: a stub session factory + a sample endpoint that reports
# what `get_override` returns under the contextvar populated by the
# middleware.
# ---------------------------------------------------------------------------


class _StubResult:
    class _Row:
        def __init__(self, rid: str, sv: str, txt: str) -> None:
            self.resource_id = rid
            self.source_version = sv
            self.translated_text = txt

    def __init__(self, rows: list[tuple[str, str, str]]) -> None:
        self._rows = [self._Row(*r) for r in rows]

    def fetchall(self):
        return self._rows


class _StubSession:
    def __init__(
        self, rows: list[tuple[str, str, str]], *, raise_on_execute: bool = False
    ) -> None:
        self._rows = rows
        self.raise_on_execute = raise_on_execute
        self.calls = 0
        self.last_params: dict[str, Any] | None = None

    async def execute(self, statement, params=None):
        self.calls += 1
        if self.raise_on_execute:
            raise RuntimeError("db down")
        self.last_params = params
        return _StubResult(self._rows)


def _factory_for(session: _StubSession):
    @asynccontextmanager
    async def factory():
        yield session
    return factory


def _build_app(
    session: _StubSession,
    *,
    resolve_locale,
) -> Starlette:
    """Wire a minimal Starlette app with the override middleware and a
    single endpoint that queries `get_override` for assertion."""

    async def lookup(request: Request) -> JSONResponse:
        text_arg = request.query_params.get("text", "")
        lang_arg = request.query_params.get("lang", "")
        # Engine-shape key: ui.engine_string.<english>
        key = f"ui.engine_string.{text_arg}" if text_arg else ""
        override = get_override(key, text_arg, lang_arg)
        return JSONResponse({"override": override})

    app = Starlette(routes=[Route("/lookup", endpoint=lookup)])
    app.add_middleware(
        SupportLocaleOverridesMiddleware,
        session_factory=_factory_for(session),
        resolve_locale=resolve_locale,
    )
    return app


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_middleware_prefetches_and_exposes_via_contextvar():
    rows = [("ui.engine_string.Learn", _sv("Learn"), "Học")]
    session = _StubSession(rows=rows)
    app = _build_app(
        session,
        resolve_locale=lambda req: req.headers.get("x-kielo-support-language", ""),
    )
    client = TestClient(app)

    resp = client.get(
        "/lookup",
        params={"text": "Learn", "lang": "vi"},
        headers={"x-kielo-support-language": "vi"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"override": "Học"}
    assert session.calls == 1
    assert session.last_params == {
        "resource_type": "ui.string",
        "language_code": "vi",
    }


def test_middleware_skips_db_for_english_locale():
    rows = [("ui.engine_string.Learn", _sv("Learn"), "Học")]
    session = _StubSession(rows=rows)
    app = _build_app(session, resolve_locale=lambda req: "en")
    client = TestClient(app)

    resp = client.get("/lookup", params={"text": "Learn", "lang": "en"})
    assert resp.status_code == 200
    assert resp.json() == {"override": None}
    # English path MUST NOT touch the DB.
    assert session.calls == 0


def test_middleware_skips_db_for_empty_locale():
    rows = [("ui.engine_string.Learn", _sv("Learn"), "Học")]
    session = _StubSession(rows=rows)
    app = _build_app(session, resolve_locale=lambda req: "")
    client = TestClient(app)

    resp = client.get("/lookup", params={"text": "Learn", "lang": ""})
    assert resp.status_code == 200
    assert resp.json() == {"override": None}
    assert session.calls == 0


# ---------------------------------------------------------------------------
# Fail-open contract
# ---------------------------------------------------------------------------


def test_middleware_fails_open_when_resolver_raises():
    """Resolver raising MUST NOT crash the request. Treat as 'no
    locale resolved' → no prefetch → no overrides."""
    session = _StubSession(rows=[("ui.engine_string.Learn", _sv("Learn"), "Học")])

    def boom(_request):
        raise RuntimeError("bad resolver")

    app = _build_app(session, resolve_locale=boom)
    client = TestClient(app)

    resp = client.get("/lookup", params={"text": "Learn", "lang": "vi"})
    assert resp.status_code == 200
    assert resp.json() == {"override": None}
    assert session.calls == 0


def test_middleware_fails_open_when_prefetch_raises():
    """DB outage during prefetch MUST NOT crash the request. Falls
    through to seed values."""
    session = _StubSession(rows=[], raise_on_execute=True)
    app = _build_app(session, resolve_locale=lambda req: "vi")
    client = TestClient(app)

    resp = client.get("/lookup", params={"text": "Learn", "lang": "vi"})
    assert resp.status_code == 200
    assert resp.json() == {"override": None}


# ---------------------------------------------------------------------------
# Request isolation
# ---------------------------------------------------------------------------


def test_middleware_does_not_leak_overrides_between_requests():
    """Each request gets its own contextvar scope. Test that a request
    with overrides set doesn't pollute a subsequent request that has
    none."""
    session = _StubSession(rows=[("ui.engine_string.Learn", _sv("Learn"), "Học")])

    # Returns vi on the first call, en on the second.
    state = {"call": 0}

    def resolver(_request):
        state["call"] += 1
        return "vi" if state["call"] == 1 else "en"

    app = _build_app(session, resolve_locale=resolver)
    client = TestClient(app)

    first = client.get("/lookup", params={"text": "Learn", "lang": "vi"})
    assert first.json() == {"override": "Học"}

    second = client.get("/lookup", params={"text": "Learn", "lang": "vi"})
    # Second request resolves to "en" → no overrides loaded → get_override
    # returns None regardless of what the caller passes for `lang`
    # because the prefetched-locale mismatch guard fires.
    assert second.json() == {"override": None}
