"""Tests for `kielo_shared.middleware.legacy_alias`.

Verifies the wire-shape contract of `DeprecationMiddleware` and
`LegacyAliasMiddleware`:

  * Deprecation/Sunset/Link headers always present on responses from
    matching paths.
  * Sunset value formatted as RFC 7231 IMF-fixdate, locale-independent.
  * Counter increments happen pre-handler (so 4xx/5xx requests count
    too) — verified by exercising a 404 path the v1 sub-app accepts.
  * Path scoping via `path_prefix` truly leaves non-matching requests
    untouched (no headers, no counter increment).
  * Default v1→v3 successor derivation handles both `/api/v1` and
    `/klearn/api/v1` shapes; `successor_path` overrides take precedence.
  * `LegacyAliasMiddleware` with empty service or successor is a soft
    no-op (no panic at registration).
"""
from __future__ import annotations

import datetime as _dt

import pytest

prometheus_client = pytest.importorskip("prometheus_client")
fastapi = pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from fastapi import FastAPI, HTTPException  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from kielo_shared.middleware.legacy_alias import (  # noqa: E402
    DeprecationMiddleware,
    LegacyAliasMiddleware,
    _default_v1_to_v3,
    _rfc7231,
)
from kielo_shared.observability import metrics as m  # noqa: E402


# ─────────────────────────────── helpers ─────────────────────────────────


def _counter_value(metric, **labels) -> float:
    """Read the current value of a labelled Counter sample."""
    return metric.labels(**labels)._value.get()  # type: ignore[attr-defined]


def _build_v1_app() -> FastAPI:
    """Build a tiny FastAPI app with both /klearn/api/v1 and /klearn/api/v3
    routes plus a /health probe outside the prefix, so middleware path
    scoping can be exercised end-to-end."""
    app = FastAPI()

    @app.get("/klearn/api/v1/sessions")
    def _v1_sessions():
        return {"ok": True, "version": "v1"}

    @app.get("/klearn/api/v1/sessions/{session_id}")
    def _v1_session_detail(session_id: str):
        return {"ok": True, "id": session_id}

    @app.get("/klearn/api/v3/sessions")
    def _v3_sessions():
        return {"ok": True, "version": "v3"}

    @app.get("/health")
    def _health():
        return {"ok": True}

    @app.get("/klearn/api/v1/boom")
    def _v1_boom():
        raise HTTPException(status_code=500, detail="boom")

    return app


# ───────────────────────────── unit-level ────────────────────────────────


def test_rfc7231_format_is_locale_independent():
    """Sunset header MUST emit English day/month abbreviations even on
    locales that would otherwise translate them via strftime."""
    d = _dt.datetime(2026, 8, 1, 12, 30, 45, tzinfo=_dt.timezone.utc)
    assert _rfc7231(d) == "Sat, 01 Aug 2026 12:30:45 GMT"


def test_default_v1_to_v3_handles_klearn_prefix():
    assert (
        _default_v1_to_v3("/klearn/api/v1/sessions")
        == "/klearn/api/v3/sessions"
    )


def test_default_v1_to_v3_handles_public_prefix():
    assert _default_v1_to_v3("/api/v1/me") == "/api/v3/me"


def test_default_v1_to_v3_passthrough_for_unmatched():
    assert _default_v1_to_v3("/health") == "/health"


# ─────────────────────────── DeprecationMiddleware ───────────────────────


def test_deprecation_headers_on_v1_response():
    app = _build_v1_app()
    app.add_middleware(
        DeprecationMiddleware,
        service="kielolearn-engine-test-headers",
        path_prefix="/klearn/api/v1",
    )
    client = TestClient(app)

    r = client.get("/klearn/api/v1/sessions")
    assert r.status_code == 200
    assert r.headers["Deprecation"] == "true"
    assert "GMT" in r.headers["Sunset"]
    assert r.headers["Link"] == (
        '</klearn/api/v3/sessions>; rel="successor-version"'
    )


def test_deprecation_skips_non_matching_path_prefix():
    app = _build_v1_app()
    app.add_middleware(
        DeprecationMiddleware,
        service="kielolearn-engine-test-skip",
        path_prefix="/klearn/api/v1",
    )
    client = TestClient(app)

    r = client.get("/klearn/api/v3/sessions")
    assert r.status_code == 200
    assert "Deprecation" not in r.headers
    assert "Sunset" not in r.headers
    assert "Link" not in r.headers

    r2 = client.get("/health")
    assert r2.status_code == 200
    assert "Deprecation" not in r2.headers


def test_deprecation_counts_5xx_responses_too():
    """Counter MUST increment before the handler runs so 5xx requests
    are counted — that's how we know if a deprecated route is still
    being exercised even when it's failing."""
    service = "kielolearn-engine-test-5xx"
    app = _build_v1_app()
    app.add_middleware(
        DeprecationMiddleware,
        service=service,
        path_prefix="/klearn/api/v1",
    )
    client = TestClient(app)

    before = _counter_value(
        m.V1_ROUTE_HITS_TOTAL,
        service=service,
        method="GET",
        path="/klearn/api/v1/boom",
    )
    r = client.get("/klearn/api/v1/boom")
    # FastAPI default 500 handler returns the canonical error envelope.
    assert r.status_code == 500
    after = _counter_value(
        m.V1_ROUTE_HITS_TOTAL,
        service=service,
        method="GET",
        path="/klearn/api/v1/boom",
    )
    assert after - before == 1.0
    # Headers also ride out on the 5xx response.
    assert r.headers.get("Deprecation") == "true"


def test_deprecation_path_template_used_not_request_url():
    """`path` label MUST be the route template so cardinality stays
    bounded by the route table size, not the request space."""
    service = "kielolearn-engine-test-template"
    app = _build_v1_app()
    app.add_middleware(
        DeprecationMiddleware,
        service=service,
        path_prefix="/klearn/api/v1",
    )
    client = TestClient(app)

    client.get("/klearn/api/v1/sessions/alpha")
    client.get("/klearn/api/v1/sessions/beta")
    client.get("/klearn/api/v1/sessions/gamma")

    # All three requests collapse to the same template label.
    template_value = _counter_value(
        m.V1_ROUTE_HITS_TOTAL,
        service=service,
        method="GET",
        path="/klearn/api/v1/sessions/{session_id}",
    )
    assert template_value >= 3.0

    # And no per-request URL leaked through as its own label series.
    for url_leak in ("/klearn/api/v1/sessions/alpha",
                     "/klearn/api/v1/sessions/beta"):
        try:
            leak_value = _counter_value(
                m.V1_ROUTE_HITS_TOTAL,
                service=service,
                method="GET",
                path=url_leak,
            )
        except Exception:  # noqa: BLE001
            leak_value = 0.0
        assert leak_value == 0.0


def test_deprecation_successor_override():
    app = _build_v1_app()
    app.add_middleware(
        DeprecationMiddleware,
        service="kielolearn-engine-test-override",
        successor_path="/api/v3/me/recommendations/articles",
        path_prefix="/klearn/api/v1",
    )
    client = TestClient(app)

    r = client.get("/klearn/api/v1/sessions")
    assert r.headers["Link"] == (
        '</api/v3/me/recommendations/articles>; rel="successor-version"'
    )


def test_deprecation_skip_callback_suppresses_headers_and_metric():
    service = "kielolearn-engine-test-skipcb"
    app = _build_v1_app()
    app.add_middleware(
        DeprecationMiddleware,
        service=service,
        path_prefix="/klearn/api/v1",
        skip=lambda req: req.url.path.endswith("/sessions"),
    )
    client = TestClient(app)

    before = _counter_value(
        m.V1_ROUTE_HITS_TOTAL,
        service=service,
        method="GET",
        path="/klearn/api/v1/sessions",
    )
    r = client.get("/klearn/api/v1/sessions")
    after = _counter_value(
        m.V1_ROUTE_HITS_TOTAL,
        service=service,
        method="GET",
        path="/klearn/api/v1/sessions",
    )
    assert r.status_code == 200
    assert "Deprecation" not in r.headers
    assert after == before


def test_deprecation_sunset_header_is_rfc7231():
    fixed = _dt.datetime(2026, 8, 1, 0, 0, 0, tzinfo=_dt.timezone.utc)
    app = _build_v1_app()
    app.add_middleware(
        DeprecationMiddleware,
        service="kielolearn-engine-test-sunset",
        sunset=fixed,
        path_prefix="/klearn/api/v1",
    )
    client = TestClient(app)

    r = client.get("/klearn/api/v1/sessions")
    assert r.headers["Sunset"] == "Sat, 01 Aug 2026 00:00:00 GMT"


# ─────────────────────────── LegacyAliasMiddleware ───────────────────────


def test_legacy_alias_headers_and_counter():
    service = "mobile-bff-test-alias"
    successor = "/api/v3/me/recommendations/articles"
    app = FastAPI()

    @app.get("/api/v3/feed")
    def _feed():
        return {"ok": True}

    app.add_middleware(
        LegacyAliasMiddleware,
        service=service,
        successor_path=successor,
        path_prefix="/api/v3/feed",
    )
    client = TestClient(app)

    before = _counter_value(
        m.LEGACY_ALIAS_HITS_TOTAL,
        service=service,
        path="/api/v3/feed",
        successor=successor,
    )
    r = client.get("/api/v3/feed")
    after = _counter_value(
        m.LEGACY_ALIAS_HITS_TOTAL,
        service=service,
        path="/api/v3/feed",
        successor=successor,
    )

    assert r.status_code == 200
    assert r.headers["Deprecation"] == "true"
    assert r.headers["Link"] == f'<{successor}>; rel="successor-version"'
    assert after - before == 1.0


def test_legacy_alias_noop_when_misconfigured():
    """Empty service or successor MUST NOT raise at registration —
    a typo shouldn't take down the whole service."""
    app = FastAPI()

    @app.get("/api/v3/feed")
    def _feed():
        return {"ok": True}

    app.add_middleware(
        LegacyAliasMiddleware,
        service="",
        successor_path="",
    )
    client = TestClient(app)

    r = client.get("/api/v3/feed")
    assert r.status_code == 200
    # No deprecation headers — middleware silently no-ops.
    assert "Deprecation" not in r.headers
