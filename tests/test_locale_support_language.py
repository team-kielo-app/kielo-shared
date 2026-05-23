"""Tests for ``kielo_shared.locale.resolve_support_language_stateless``.

Mirrors the Go-side test cases in
``kielo-shared/middleware/support_language_test.go`` so the two
implementations stay in lockstep. Each test name corresponds 1:1 with
its Go sibling (s/Test_/test_/, s/CamelCase/snake_case/).

Verifies the ADR-006 §3.83 resolution chain end-to-end:

  * Explicit ``?support_language_code=`` query wins over everything.
  * ``Accept-Language`` header parses BCP47, prefers first supported match.
  * Unsupported Accept-Language values fall through (don't poison
    downstream code with codes that have no display name).
  * Active learning language (contextvar) is used as a fallback when
    no explicit support-language signal is present.
  * Defaults to ``TIER_A_SUPPORT_LOCALE`` when no source matches.
  * Explicit signals always beat the learning-language contextvar.
"""

from __future__ import annotations

import pytest

starlette_testclient = pytest.importorskip("starlette.testclient")
fastapi = pytest.importorskip("fastapi")

from fastapi import FastAPI, Request  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from kielo_shared.db_utils import (  # noqa: E402
    reset_active_language,
    set_active_language,
)
from kielo_shared.locale import (  # noqa: E402
    is_supported_support_language,
    resolve_support_language_stateless,
)
from kielo_shared.locale_constants import TIER_A_SUPPORT_LOCALE  # noqa: E402


def _make_app() -> FastAPI:
    """Tiny FastAPI app whose only route echoes the resolved support
    language back as the response body. Keeps the tests free of
    Request-construction boilerplate while exercising the real
    Starlette query_params / headers surface the helper reads from."""
    app = FastAPI()

    @app.get("/x")
    async def _resolve(request: Request) -> dict:
        return {"resolved": resolve_support_language_stateless(request)}

    return app


@pytest.fixture
def client() -> TestClient:
    return TestClient(_make_app())


# ---------------------------------------------------------------------------
# Mirror tests — one-to-one with the Go-side cases in
# support_language_test.go. Names match modulo casing convention.
# ---------------------------------------------------------------------------


def test_resolve_support_language_explicit_query_wins(client: TestClient):
    """Explicit ?support_language_code= must beat Accept-Language."""
    r = client.get("/x?support_language_code=fi", headers={"Accept-Language": "vi"})
    assert r.json() == {"resolved": "fi"}


def test_resolve_support_language_accept_language_header(client: TestClient):
    """Accept-Language must parse BCP47 and prefer the first supported match."""
    r = client.get("/x", headers={"Accept-Language": "vi-VN,vi;q=0.9,en;q=0.5"})
    assert r.json() == {"resolved": "vi"}


def test_resolve_support_language_accept_language_picks_supported_only(
    client: TestClient,
):
    """Unsupported Accept-Language codes must fall through to the default.

    `xh-ZA` (isiXhosa, South Africa) is not in LANGUAGE_DISPLAY_NAMES.
    Returning it would push an unsupported code into downstream code
    that assumes a known display name; resolver must skip and continue.
    """
    r = client.get("/x", headers={"Accept-Language": "xh-ZA"})
    assert r.json() == {"resolved": TIER_A_SUPPORT_LOCALE}


def test_resolve_support_language_learning_language_context_fallback(
    client: TestClient,
):
    """When no query/header signal is present, the active learning
    language contextvar (set by ActiveLanguageMiddleware) must be
    used as the support-language fallback."""
    token = set_active_language("fi")
    try:
        r = client.get("/x")
    finally:
        reset_active_language(token)
    assert r.json() == {"resolved": "fi"}


def test_resolve_support_language_defaults_to_tier_a(client: TestClient):
    """No query, no header, no contextvar → falls through to ``en``."""
    r = client.get("/x")
    assert r.json() == {"resolved": TIER_A_SUPPORT_LOCALE}


def test_resolve_support_language_query_wins_over_context(client: TestClient):
    """Explicit query param must beat the learning-language contextvar."""
    token = set_active_language("fi")
    try:
        r = client.get("/x?support_language_code=sv")
    finally:
        reset_active_language(token)
    assert r.json() == {"resolved": "sv"}


def test_resolve_support_language_header_wins_over_context(client: TestClient):
    """Accept-Language must beat the learning-language contextvar."""
    token = set_active_language("fi")
    try:
        r = client.get("/x", headers={"Accept-Language": "vi"})
    finally:
        reset_active_language(token)
    assert r.json() == {"resolved": "vi"}


# ---------------------------------------------------------------------------
# Additional Python-only coverage. Not mirrored from Go because Go's
# test suite uses Echo's QueryParam directly (no equivalent
# whitespace/empty-string surface).
# ---------------------------------------------------------------------------


def test_resolve_support_language_whitespace_query_falls_through(client: TestClient):
    """Whitespace-only query param must not short-circuit the chain."""
    r = client.get("/x?support_language_code=   ", headers={"Accept-Language": "fi"})
    assert r.json() == {"resolved": "fi"}


def test_resolve_support_language_invalid_query_falls_through(client: TestClient):
    """Query param that doesn't normalize to a supported support-locale
    must fall through to the next source. The mobile app occasionally
    sends raw locale strings (``en-US`` is fine, ``xx`` is not); the
    resolver must keep walking the chain rather than locking in a
    code that has no display name."""
    r = client.get("/x?support_language_code=xx", headers={"Accept-Language": "fi"})
    assert r.json() == {"resolved": "fi"}


def test_resolve_support_language_normalizes_locale_alias(client: TestClient):
    """``vn`` is a known alias for ``vi`` (Vietnamese) handled by
    ``normalize_locale_code``; the resolver must accept it."""
    r = client.get("/x?support_language_code=vn")
    assert r.json() == {"resolved": "vi"}


# ---------------------------------------------------------------------------
# is_supported_support_language predicate.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code,expected",
    [
        ("en", True),
        ("fi", True),
        ("sv", True),
        ("vi", True),
        ("EN", True),  # case-insensitive via normalize_locale_code
        ("vi-VN", True),  # region stripped by normalize_locale_code
        ("vn", True),  # vi alias handled by normalize_locale_code
        ("xx", False),
        ("xh-ZA", False),
        ("", False),
        (None, False),
    ],
)
def test_is_supported_support_language(code, expected):
    assert is_supported_support_language(code) is expected


# ---------------------------------------------------------------------------
# FastAPI dependency wrapper. Distinct test surface so a regression in the
# Depends() integration surfaces separately from a resolver bug.
# ---------------------------------------------------------------------------


def test_get_support_language_dependency_resolves_through_depends():
    """The Depends() wrapper must produce identical output to calling
    resolve_support_language_stateless directly. Exercise the FastAPI
    dependency-injection path end-to-end via TestClient."""
    from fastapi import Depends, FastAPI
    from kielo_shared.locale.fastapi import get_support_language

    app = FastAPI()

    @app.get("/y")
    async def _read(support_language_code: str = Depends(get_support_language)) -> dict:
        return {"resolved": support_language_code}

    c = TestClient(app)
    # Explicit query wins.
    assert c.get("/y?support_language_code=fi").json() == {"resolved": "fi"}
    # Accept-Language as fallback.
    assert c.get("/y", headers={"Accept-Language": "vi"}).json() == {"resolved": "vi"}
    # No signal → tier A.
    assert c.get("/y").json() == {"resolved": TIER_A_SUPPORT_LOCALE}
