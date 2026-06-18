"""Tests for `kielo_shared.observability.metrics.llm_generate_validate_emit`.

Pins the bounded-cardinality contract for the F-lite generate+validate
metric family. This is the only metric in the seam-telemetry batch
where the error label originates from caller-supplied strings, so the
sanitizer must drop:
  * counts and indices  (`too_few_words:N<5`, `example_3_missing_text`)
  * proper-noun values  (`duplicate_term:hund`)
  * exception messages  (`provider_failure:RuntimeError("foo")`)
And cap label length so a runaway error string never explodes
cardinality.
"""
from __future__ import annotations

import pytest

prometheus_client = pytest.importorskip("prometheus_client")

from kielo_shared.observability import metrics as m  # noqa: E402


def _label_set_for_counter(metric, label_name: str) -> set[str]:
    """Snapshot every label value seen so far for a Counter."""
    values: set[str] = set()
    for sample in metric.collect():
        for s in sample.samples:
            if s.name.endswith("_total"):
                v = s.labels.get(label_name)
                if v is not None:
                    values.add(v)
    return values


# ─────────────────────── sanitizer unit tests ───────────────────────


def test_sanitize_strips_value_after_colon():
    assert m._sanitize_error_class("too_few_words:N<5") == "too_few_words"
    assert m._sanitize_error_class("duplicate_term:hund") == "duplicate_term"
    assert m._sanitize_error_class("provider_failure:RuntimeError") == "provider_failure"


def test_sanitize_strips_inline_index():
    assert m._sanitize_error_class("example_0_missing_text") == "example_missing_text"
    assert m._sanitize_error_class("example_12_missing_translation") == (
        "example_missing_translation"
    )


def test_sanitize_strips_trailing_index():
    assert m._sanitize_error_class("step_3") == "step"


def test_sanitize_lowercases_and_caps_length():
    big = "X" * 200
    assert len(m._sanitize_error_class(big)) <= 64
    assert m._sanitize_error_class("MISSING_TITLE") == "missing_title"


def test_sanitize_empty_returns_empty():
    assert m._sanitize_error_class("") == ""
    assert m._sanitize_error_class(None) == ""


# ────────────────── emitter integration with prometheus_client ──────────────


def test_emitter_increments_total_for_valid_call_with_empty_error_class():
    before = m.LLM_GENERATE_VALIDATE_TOTAL.labels(
        task="micro_drill_baseword",
        valid="true",
        cached="false",
        error_class="",
    )._value.get()  # type: ignore[attr-defined]
    m.llm_generate_validate_emit(
        task="micro_drill_baseword",
        prompt_version="v1",
        valid=True,
        cached=False,
        attempts=1,
        validation_errors=None,
    )
    after = m.LLM_GENERATE_VALIDATE_TOTAL.labels(
        task="micro_drill_baseword",
        valid="true",
        cached="false",
        error_class="",
    )._value.get()  # type: ignore[attr-defined]
    assert after - before == 1.0


def test_emitter_uses_sanitized_error_class_label():
    m.llm_generate_validate_emit(
        task="topic_list_prompt_vocab",
        prompt_version="v1",
        valid=False,
        cached=False,
        attempts=2,
        validation_errors=["too_few_words:2<5", "duplicate_term:foo"],
    )
    seen = _label_set_for_counter(m.LLM_GENERATE_VALIDATE_TOTAL, "error_class")
    # Sanitized to bucket name.
    assert "too_few_words" in seen
    # Raw value (with `:N<5`) MUST NOT appear.
    assert all(":" not in v for v in seen)
    # Term value (`hund`) MUST NOT appear as a standalone label.
    assert "hund" not in seen


def test_emitter_cached_unknown_when_none():
    m.llm_generate_validate_emit(
        task="unit_test_cached_none",
        prompt_version="v1",
        valid=False,
        cached=None,
        attempts=2,
        validation_errors=["empty_words_list"],
    )
    seen = _label_set_for_counter(m.LLM_GENERATE_VALIDATE_TOTAL, "cached")
    assert "unknown" in seen


def test_emitter_cached_true_partition_distinct_from_false():
    m.llm_generate_validate_emit(
        task="unit_test_cached_partition",
        prompt_version="v1",
        valid=True,
        cached=True,
        attempts=1,
        validation_errors=None,
    )
    m.llm_generate_validate_emit(
        task="unit_test_cached_partition",
        prompt_version="v1",
        valid=True,
        cached=False,
        attempts=1,
        validation_errors=None,
    )
    cached_true = m.LLM_GENERATE_VALIDATE_TOTAL.labels(
        task="unit_test_cached_partition",
        valid="true",
        cached="true",
        error_class="",
    )._value.get()  # type: ignore[attr-defined]
    cached_false = m.LLM_GENERATE_VALIDATE_TOTAL.labels(
        task="unit_test_cached_partition",
        valid="true",
        cached="false",
        error_class="",
    )._value.get()  # type: ignore[attr-defined]
    assert cached_true >= 1.0
    assert cached_false >= 1.0


def test_emitter_attempts_observed_in_histogram():
    m.llm_generate_validate_emit(
        task="unit_test_attempts",
        prompt_version="v1",
        valid=False,
        cached=False,
        attempts=2,
        validation_errors=["empty_steps"],
    )
    samples = list(m.LLM_GENERATE_VALIDATE_ATTEMPTS.collect())
    found = False
    for sample_family in samples:
        for s in sample_family.samples:
            if (
                s.name == "kielo_llm_generate_validate_attempts_count"
                and s.labels.get("task") == "unit_test_attempts"
                and s.labels.get("valid") == "false"
            ):
                assert s.value >= 1.0
                found = True
    assert found, "attempts histogram must record per-call observations"


def test_emitter_label_set_excludes_raw_prompt_or_user_text():
    """The metric MUST NOT accept arbitrary strings as labels — only
    `task` (caller-controlled but stable), `valid` / `cached` (booleans),
    `error_class` (sanitized). Construct a contrived call where the
    validation_errors string contains chars typical of user input
    (whitespace, punctuation, non-ascii) and assert the resulting label
    is the sanitized class name only — no raw text leak."""
    m.llm_generate_validate_emit(
        task="unit_test_no_raw_text",
        prompt_version="v1",
        valid=False,
        cached=False,
        attempts=2,
        validation_errors=[
            "duplicate_term:Käytäntö! With spaces and 字符",
            "ignored_secondary",
        ],
    )
    seen = _label_set_for_counter(m.LLM_GENERATE_VALIDATE_TOTAL, "error_class")
    assert "duplicate_term" in seen
    # No fragment of the raw user-ish text leaks through.
    for v in seen:
        assert "Käytäntö" not in v
        assert " " not in v
        assert "字符" not in v
        assert "!" not in v


def test_emitter_no_raise_when_prometheus_disabled(monkeypatch):
    """If PROMETHEUS_AVAILABLE is False the emitter still logs and
    returns silently — never raises — so import sites stay safe."""
    monkeypatch.setattr(m, "PROMETHEUS_AVAILABLE", False)
    m.llm_generate_validate_emit(
        task="unit_test_no_prom",
        prompt_version="v1",
        valid=True,
        cached=False,
        attempts=1,
        validation_errors=None,
    )
