"""Phase D+3.2 transition cleanup — log-level policy pin.

Once Prometheus metrics carry the durable runtime signal, the
per-call success-path logs become noise. Each emitter downgrades
its happy-path log to DEBUG and keeps INFO only for error /
degradation paths. This test ratchets the policy so a future
revert (or a copy-paste of an old emitter pattern that always
logs INFO) trips CI.
"""
from __future__ import annotations

import logging

import pytest

from kielo_shared.observability import metrics as m


def _capture(caplog, level: int = logging.DEBUG):
    return caplog.at_level(level, logger=m.logger.name)


# ─────────────────────── llm_emit ───────────────────────


def test_llm_emit_success_logs_at_debug(caplog):
    with _capture(caplog):
        m.llm_emit({"provider": "p", "task": "t", "error": ""})
    levels = {r.levelno for r in caplog.records if "llm_call" in r.message}
    assert logging.INFO not in levels, "success path must not log at INFO"
    assert logging.DEBUG in levels


def test_llm_emit_failure_logs_at_info(caplog):
    with _capture(caplog):
        m.llm_emit({"provider": "p", "task": "t", "error": "timeout"})
    levels = {r.levelno for r in caplog.records if "llm_call" in r.message}
    assert logging.INFO in levels


# ─────────────────────── localization_emit ─────────────────


def test_localization_emit_success_logs_at_debug(caplog):
    with _capture(caplog):
        m.localization_emit({
            "provider": "p", "source_locale": "fi", "target_locale": "en", "error": "",
        })
    levels = {r.levelno for r in caplog.records if "localization_batch" in r.message}
    assert logging.INFO not in levels
    assert logging.DEBUG in levels


def test_localization_emit_failure_logs_at_info(caplog):
    with _capture(caplog):
        m.localization_emit({
            "provider": "p", "source_locale": "fi", "target_locale": "en",
            "error": "pair_unavailable",
        })
    levels = {r.levelno for r in caplog.records if "localization_batch" in r.message}
    assert logging.INFO in levels


# ─────────────────────── pubsub_publish_emit ───────────────


def test_pubsub_publish_success_logs_at_debug(caplog):
    with _capture(caplog):
        m.pubsub_publish_emit(service="s", topic="t", error=False, latency_seconds=0.05)
    levels = {r.levelno for r in caplog.records if "pubsub_publish" in r.message}
    assert logging.INFO not in levels
    assert logging.DEBUG in levels


def test_pubsub_publish_skipped_logs_at_debug(caplog):
    with _capture(caplog):
        m.pubsub_publish_emit(service="s", topic="t", skipped=True)
    levels = {r.levelno for r in caplog.records if "pubsub_publish" in r.message}
    assert logging.INFO not in levels


def test_pubsub_publish_error_logs_at_info(caplog):
    with _capture(caplog):
        m.pubsub_publish_emit(service="s", topic="t", error=True, latency_seconds=0.5)
    levels = {r.levelno for r in caplog.records if "pubsub_publish" in r.message}
    assert logging.INFO in levels


# ─────────────────────── pubsub_ack_emit ───────────────────


@pytest.mark.parametrize("outcome", ["ack", "drop"])
def test_pubsub_ack_quiet_outcome_logs_at_debug(caplog, outcome):
    with _capture(caplog):
        m.pubsub_ack_emit(service="s", topic="t", outcome=outcome)
    levels = {r.levelno for r in caplog.records if "pubsub_ack" in r.message}
    assert logging.INFO not in levels
    assert logging.DEBUG in levels


@pytest.mark.parametrize("outcome", ["nack", "deadletter"])
def test_pubsub_ack_degradation_outcome_logs_at_info(caplog, outcome):
    with _capture(caplog):
        m.pubsub_ack_emit(service="s", topic="t", outcome=outcome)
    levels = {r.levelno for r in caplog.records if "pubsub_ack" in r.message}
    assert logging.INFO in levels


# ─────────────────────── tts_cache_emit ───────────────────


def test_tts_cache_always_logs_at_debug(caplog):
    with _capture(caplog):
        m.tts_cache_emit(caller="convo_greeting_prime", outcome="hit")
        m.tts_cache_emit(caller="convo_greeting_prime", outcome="miss")
    levels = {r.levelno for r in caplog.records if "tts_cache" in r.message}
    assert logging.INFO not in levels
    assert logging.DEBUG in levels


# ─────────────────────── llm_generate_validate_emit ────────


def test_llm_generate_validate_success_logs_at_debug(caplog):
    with _capture(caplog):
        m.llm_generate_validate_emit(
            task="t", prompt_version="v1", valid=True, attempts=1,
        )
    levels = {r.levelno for r in caplog.records if "llm_generate_validate" in r.message}
    assert logging.INFO not in levels
    assert logging.DEBUG in levels


def test_llm_generate_validate_failure_logs_at_info(caplog):
    with _capture(caplog):
        m.llm_generate_validate_emit(
            task="t", prompt_version="v1", valid=False, attempts=2,
            validation_errors=["empty_examples"],
        )
    levels = {r.levelno for r in caplog.records if "llm_generate_validate" in r.message}
    assert logging.INFO in levels


# ─────────────────────── idempotency_emit ───────────────────────


@pytest.mark.parametrize("result", ["started", "hit"])
def test_idempotency_quiet_outcome_logs_at_debug(caplog, result):
    with _capture(caplog):
        m.idempotency_emit(namespace="topic_list_prompt", result=result, latency_seconds=0.05)
    levels = {r.levelno for r in caplog.records if "idempotency" in r.message}
    assert logging.INFO not in levels
    assert logging.DEBUG in levels


@pytest.mark.parametrize("result", ["in_progress", "conflict", "failed", "error"])
def test_idempotency_actionable_outcome_logs_at_info(caplog, result):
    with _capture(caplog):
        m.idempotency_emit(namespace="topic_list_prompt", result=result, latency_seconds=0.5)
    levels = {r.levelno for r in caplog.records if "idempotency" in r.message}
    assert logging.INFO in levels
