"""Tests for `kielo_shared.observability.tts_cache_emit`.

Pins the bounded-cardinality contract for the TTS caller-side
cache outcome counter. Mirrors the shape of
`test_metrics_generate_validate.py`.
"""
from __future__ import annotations

import pytest

prometheus_client = pytest.importorskip("prometheus_client")

from kielo_shared.observability import metrics as m  # noqa: E402
from kielo_shared.observability import tts_cache_emit  # noqa: E402


def _label_values(metric, label_name: str) -> set[str]:
    values: set[str] = set()
    for sample_family in metric.collect():
        for s in sample_family.samples:
            if s.name.endswith("_total"):
                v = s.labels.get(label_name)
                if v is not None:
                    values.add(v)
    return values


def test_emitter_increments_for_hit_outcome():
    before = m.TTS_CACHE_RESULT_TOTAL.labels(
        caller="klearn_tts_baseword", outcome="hit"
    )._value.get()  # type: ignore[attr-defined]
    tts_cache_emit(caller="klearn_tts_baseword", outcome="hit")
    after = m.TTS_CACHE_RESULT_TOTAL.labels(
        caller="klearn_tts_baseword", outcome="hit"
    )._value.get()  # type: ignore[attr-defined]
    assert after - before == 1.0


def test_emitter_partitions_hit_vs_miss_for_same_caller():
    tts_cache_emit(caller="convo_greeting_prime", outcome="hit")
    tts_cache_emit(caller="convo_greeting_prime", outcome="hit")
    tts_cache_emit(caller="convo_greeting_prime", outcome="miss")

    hit = m.TTS_CACHE_RESULT_TOTAL.labels(
        caller="convo_greeting_prime", outcome="hit"
    )._value.get()  # type: ignore[attr-defined]
    miss = m.TTS_CACHE_RESULT_TOTAL.labels(
        caller="convo_greeting_prime", outcome="miss"
    )._value.get()  # type: ignore[attr-defined]
    assert hit >= 2.0
    assert miss >= 1.0


def test_emitter_label_set_remains_bounded():
    """Caller is pinned per call-site; outcome is a 2-value enum.
    Construct a contrived emit to verify the label set stays
    constrained to the values we expect — no free-form text leak.
    """
    tts_cache_emit(caller="klearn_tts_baseword", outcome="hit")
    tts_cache_emit(caller="convo_greeting_prime", outcome="miss")

    callers = _label_values(m.TTS_CACHE_RESULT_TOTAL, "caller")
    outcomes = _label_values(m.TTS_CACHE_RESULT_TOTAL, "outcome")

    # Callers MUST appear; assert presence of the expected ones.
    assert "klearn_tts_baseword" in callers
    assert "convo_greeting_prime" in callers
    assert outcomes <= {"hit", "miss"}


def test_emitter_no_raise_when_prometheus_disabled(monkeypatch):
    monkeypatch.setattr(m, "PROMETHEUS_AVAILABLE", False)
    # Should not raise; emitter falls back to log-only.
    tts_cache_emit(caller="klearn_tts_baseword", outcome="hit")
