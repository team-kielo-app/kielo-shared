"""Tests for kielo_shared.observability.external_api."""

from __future__ import annotations

import logging

import pytest

from kielo_shared.observability import (
    classify_external_api_failure,
    external_api_failure_emit,
)
from kielo_shared.observability.external_api import LOG_TOKEN, status_of
from kielo_shared.seam.llm.types import Error as LLMError
from kielo_shared.seam.llm.types import ErrorClass as LLMErrorClass


class _Response:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _HTTPError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.response = _Response(status_code)


@pytest.mark.parametrize(
    ("status", "message", "error_class", "expected"),
    [
        (402, "", "", "quota"),
        (
            429,
            "You exceeded your current quota, please check your plan and billing",
            "",
            "quota",
        ),
        (429, "429 RESOURCE_EXHAUSTED", "", "quota"),
        (402, "PROJECT_BALANCE_INSUFFICIENT", "", "quota"),
        (429, "Too Many Requests", "", "rate_limit"),
        (401, "", "", "auth"),
        (None, "API key not valid. Please pass a valid API key.", "", "auth"),
        (None, "", "timeout", "timeout"),
        (None, "ReadTimeout: slow", "", "timeout"),
        (None, "", "connection", "connection"),
        (
            None,
            "ConnectError: [Errno 8] nodename nor servname provided",
            "",
            "connection",
        ),
        (503, "", "", "server"),
        (None, "", "http_5xx", "server"),
        (None, "", "provider_error", "server"),
        (422, "", "", "client"),
        (None, "", "", "unknown"),
    ],
)
def test_classify_external_api_failure(status, message, error_class, expected):
    assert classify_external_api_failure(status, message, error_class) == expected


def test_status_of_walks_response_and_seam_cause():
    inner = _HTTPError(402, "insufficient credits")
    assert status_of(inner) == 402
    wrapped = LLMError(LLMErrorClass.PROVIDER_ERROR, inner)
    assert status_of(wrapped) == 402
    assert status_of(RuntimeError("nope")) is None


def test_emit_writes_canonical_warning(caplog, monkeypatch):
    monkeypatch.setenv("K_SERVICE", "kielolearn-engine")
    with caplog.at_level(
        logging.WARNING, logger="kielo_shared.observability.external_api"
    ):
        external_api_failure_emit(
            provider="deepgram",
            operation="stt.speech_eval",
            exc=_HTTPError(402, "PROJECT_BALANCE_INSUFFICIENT\nsecond line"),
        )
    record = next(r for r in caplog.records if LOG_TOKEN in r.getMessage())
    message = record.getMessage()
    assert record.levelno == logging.WARNING
    for token in (
        "provider=deepgram",
        "operation=stt.speech_eval",
        "kind=quota",
        "status=402",
        "service=kielolearn-engine",
    ):
        assert token in message
    assert "\n" not in message


def test_emit_uses_seam_error_class_when_no_status(caplog):
    with caplog.at_level(
        logging.WARNING, logger="kielo_shared.observability.external_api"
    ):
        external_api_failure_emit(
            provider="openai-tts:tts-1",
            operation="tts.lesson_step",
            exc=LLMError(LLMErrorClass.TIMEOUT, RuntimeError("slow")),
            error_class="timeout",
        )
    assert any("kind=timeout" in r.getMessage() for r in caplog.records)


def test_emit_never_raises_on_garbage():
    external_api_failure_emit(provider="", operation="", exc=None, status=None)
