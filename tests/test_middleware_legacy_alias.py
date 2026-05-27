"""Tests for `kielo_shared.middleware.legacy_alias`.

Verifies the wire-shape contract of `LegacyAliasMiddleware`:

  * Deprecation/Sunset/Link headers always present on responses from
    matching paths.
  * Counter increments correctly tag the renamed v3 successor.
  * Misconfigured middleware (empty service/successor) is a soft no-op
    — a typo at registration shouldn't take down the whole service.

The companion `DeprecationMiddleware` (and its `kielo_v1_route_hits_total`
burn-down counter) was retired alongside the Python v1 router itself —
kielolearn-engine had the only remaining Python v1 surface; it was
removed when the burn-down decayed to zero traffic. See the commit
message of that change for the full survey.
"""

from __future__ import annotations

import pytest

prometheus_client = pytest.importorskip("prometheus_client")
fastapi = pytest.importorskip("fastapi")
starlette_testclient = pytest.importorskip("starlette.testclient")

from fastapi import FastAPI  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from kielo_shared.middleware.legacy_alias import (  # noqa: E402
    LegacyAliasMiddleware,
    _rfc7231,
)
from kielo_shared.observability import metrics as m  # noqa: E402


# ─────────────────────────────── helpers ─────────────────────────────────


def _counter_value(metric, **labels) -> float:
    """Read the current value of a labelled Counter sample."""
    return metric.labels(**labels)._value.get()  # type: ignore[attr-defined]


# ────────────────────────────── _rfc7231 ─────────────────────────────────


def test_rfc7231_format_is_locale_independent():
    """RFC 8594 requires the Sunset header in RFC 7231 IMF-fixdate
    format. Python's strftime is locale-sensitive for %a/%b, so the
    middleware hand-rolls day/month names. Spot-check a known date."""
    import datetime as _dt

    # 2026-08-01 was a Saturday.
    d = _dt.datetime(2026, 8, 1, 0, 0, 0, tzinfo=_dt.timezone.utc)
    assert _rfc7231(d) == "Sat, 01 Aug 2026 00:00:00 GMT"


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
