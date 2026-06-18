"""Tests for kielo_shared.observability.side_effect_failed_emit.

Covers the counter primitive used by handlers that have a primary path
+ a set of auxiliary side effects where each side-effect failure is
logged + swallowed (achievement updates, telemetry writes, cache
invalidations). The metric makes those swallows observable at the
dashboard level even when the WARN log is buried.
"""
from __future__ import annotations

import pytest

from kielo_shared.observability import side_effect_failed_emit


@pytest.fixture
def _reset_counter():
    from kielo_shared.observability import metrics as metrics_mod

    if metrics_mod.PROMETHEUS_AVAILABLE:
        metrics_mod.SIDE_EFFECT_FAILED_TOTAL.clear()
    yield
    if metrics_mod.PROMETHEUS_AVAILABLE:
        metrics_mod.SIDE_EFFECT_FAILED_TOTAL.clear()


def test_increments_counter_per_service_and_kind(_reset_counter):
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability.metrics import SIDE_EFFECT_FAILED_TOTAL

    side_effect_failed_emit(service="kielolearn-engine", kind="behavioral.achievement")
    side_effect_failed_emit(service="kielolearn-engine", kind="behavioral.achievement")
    side_effect_failed_emit(service="kielolearn-engine", kind="behavioral.skill")

    achievement_sample = SIDE_EFFECT_FAILED_TOTAL.labels(
        service="kielolearn-engine", kind="behavioral.achievement"
    )
    skill_sample = SIDE_EFFECT_FAILED_TOTAL.labels(
        service="kielolearn-engine", kind="behavioral.skill"
    )
    assert achievement_sample._value.get() == 2
    assert skill_sample._value.get() == 1


def test_accepts_optional_exception(_reset_counter):
    """`exc` arg is accepted (used by callers in their catch blocks)
    but currently doesn't change cardinality — verified by counter
    sample matching regardless of exception passed."""
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability.metrics import SIDE_EFFECT_FAILED_TOTAL

    side_effect_failed_emit(
        service="kielolearn-engine",
        kind="cache.invalidate",
        exc=RuntimeError("simulated redis timeout"),
    )
    side_effect_failed_emit(
        service="kielolearn-engine",
        kind="cache.invalidate",
        exc=None,
    )
    sample = SIDE_EFFECT_FAILED_TOTAL.labels(
        service="kielolearn-engine", kind="cache.invalidate"
    )
    assert sample._value.get() == 2


def test_no_raise_when_prometheus_disabled(monkeypatch):
    """Caller code uses this emitter inside catch blocks — it MUST
    never raise itself, otherwise it would mask the real exception
    flow. Verify the no-op path when prometheus_client is unavailable."""
    from kielo_shared.observability import metrics as metrics_mod

    monkeypatch.setattr(metrics_mod, "PROMETHEUS_AVAILABLE", False)
    # Must not raise.
    side_effect_failed_emit(service="any", kind="any")
