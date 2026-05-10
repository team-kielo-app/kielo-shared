"""Tests for `kielo_shared.seam.stt`.

Phase STT-1 factory seam. Provider tests run with a stub
`livekit.plugins.deepgram` so the suite doesn't require the real
plugin to be installed in the kielo-shared dev venv.
"""
from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from kielo_shared.seam.stt import (
    DeepgramLiveKitSTTProvider,
    Error,
    ErrorClass,
    RealtimeSTTRequest,
    class_of,
    with_metrics,
)


@pytest.fixture
def stub_deepgram(monkeypatch):
    """Inject a fake `livekit.plugins.deepgram` module so the
    provider can construct without the real plugin."""
    captured: dict[str, Any] = {}

    class _FakeSTT:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    fake_dg = types.ModuleType("livekit.plugins.deepgram")
    fake_dg.STT = _FakeSTT  # type: ignore[attr-defined]

    fake_plugins = sys.modules.setdefault(
        "livekit.plugins", types.ModuleType("livekit.plugins")
    )
    monkeypatch.setattr(fake_plugins, "deepgram", fake_dg, raising=False)
    monkeypatch.setitem(sys.modules, "livekit.plugins.deepgram", fake_dg)
    return captured


# ─────────────────────── provider unit tests ──────────────────────────


def test_provider_passes_all_fields_to_deepgram(stub_deepgram):
    p = DeepgramLiveKitSTTProvider("test-key")
    p.create_realtime_stt(
        RealtimeSTTRequest(
            task="convo_realtime_stt",
            model="nova-3",
            language="fi",
            keyterms=("hund", "katt"),
            smart_format=True,
            punctuate=True,
            filler_words=True,
        )
    )
    assert stub_deepgram["model"] == "nova-3"
    assert stub_deepgram["language"] == "fi"
    assert stub_deepgram["keyterm"] == ["hund", "katt"]
    assert stub_deepgram["smart_format"] is True
    assert stub_deepgram["punctuate"] is True
    assert stub_deepgram["filler_words"] is True


def test_provider_rejects_unsupported_language(stub_deepgram):
    p = DeepgramLiveKitSTTProvider("test-key")
    with pytest.raises(Error) as ei:
        p.create_realtime_stt(
            RealtimeSTTRequest(task="convo_realtime_stt", model="nova-3", language="de"),
        )
    assert ei.value.error_class == ErrorClass.INVALID_LANGUAGE


def test_provider_rejects_missing_model(stub_deepgram):
    p = DeepgramLiveKitSTTProvider("test-key")
    with pytest.raises(Error) as ei:
        p.create_realtime_stt(
            RealtimeSTTRequest(task="convo_realtime_stt", model="", language="fi"),
        )
    assert ei.value.error_class == ErrorClass.INVALID_REQUEST


def test_provider_propagates_api_key_to_env(monkeypatch, stub_deepgram):
    """Pre-D+3 voice_pipeline set DEEPGRAM_API_KEY in os.environ
    before constructing the plugin. Behavior preserved by the
    seam unless explicitly disabled."""
    monkeypatch.delenv("DEEPGRAM_API_KEY", raising=False)
    p = DeepgramLiveKitSTTProvider("test-key", propagate_api_key_to_env=True)
    p.create_realtime_stt(
        RealtimeSTTRequest(task="convo_realtime_stt", model="nova-3", language="fi"),
    )
    import os
    assert os.environ.get("DEEPGRAM_API_KEY") == "test-key"


def test_provider_skips_keyterms_when_empty(stub_deepgram):
    p = DeepgramLiveKitSTTProvider("test-key")
    p.create_realtime_stt(
        RealtimeSTTRequest(task="convo_realtime_stt", model="nova-3", language="fi"),
    )
    assert stub_deepgram["keyterm"] is None


def test_provider_id_is_stable_string(stub_deepgram):
    p = DeepgramLiveKitSTTProvider("k")
    assert p.provider_id == "deepgram:livekit@stt-v1"


def test_class_of_handles_seam_and_unknown(stub_deepgram):
    assert class_of(Error(ErrorClass.INVALID_LANGUAGE)) == "invalid_language"
    assert class_of(RuntimeError("x")) == "unknown"
    assert class_of(None) == ""


# ─────────────────────── decorator integration ──────────────────────────


class _StubProvider:
    def __init__(self, error: BaseException | None = None):
        self.error = error
        self.last: RealtimeSTTRequest | None = None

    @property
    def provider_id(self) -> str:
        return "stub-stt:v0"

    def create_realtime_stt(self, request: RealtimeSTTRequest) -> Any:
        self.last = request
        if self.error is not None:
            raise self.error
        return object()


def test_decorator_passes_request_through_on_success():
    stub = _StubProvider()
    dec = with_metrics(stub)
    out = dec.create_realtime_stt(
        RealtimeSTTRequest(task="convo_realtime_stt", model="nova-3", language="fi"),
    )
    assert out is not None
    assert stub.last is not None and stub.last.task == "convo_realtime_stt"


def test_decorator_preserves_provider_error():
    stub = _StubProvider(error=Error(ErrorClass.INVALID_LANGUAGE))
    dec = with_metrics(stub)
    with pytest.raises(Error) as ei:
        dec.create_realtime_stt(
            RealtimeSTTRequest(task="convo_realtime_stt", model="nova-3", language="de"),
        )
    assert ei.value.error_class == ErrorClass.INVALID_LANGUAGE


def test_decorator_increments_counter_with_bounded_labels():
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability import metrics as m

    # Success path.
    with_metrics(_StubProvider()).create_realtime_stt(
        RealtimeSTTRequest(
            task="convo_realtime_stt",
            model="nova-3",
            language="fi",
            keyterms=("a", "b", "c"),
        ),
    )
    # Error path.
    with pytest.raises(Error):
        with_metrics(
            _StubProvider(error=Error(ErrorClass.INVALID_LANGUAGE))
        ).create_realtime_stt(
            RealtimeSTTRequest(task="convo_realtime_stt", model="nova-3", language="de"),
        )

    seen_errors: set[str] = set()
    seen_languages: set[str] = set()
    for sample_family in m.STT_CALLS_TOTAL.collect():
        for s in sample_family.samples:
            if s.name.endswith("_total") and s.labels.get("task") == "convo_realtime_stt":
                seen_errors.add(s.labels.get("error", ""))
                seen_languages.add(s.labels.get("language", ""))
    assert "" in seen_errors, "success path emits empty error label"
    assert "invalid_language" in seen_errors
    assert {"fi", "de"} <= seen_languages


def test_decorator_records_keyterm_count_without_leaking_values():
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability import metrics as m

    secret_terms = ("user-private-name-1", "user-private-name-2")
    with_metrics(_StubProvider()).create_realtime_stt(
        RealtimeSTTRequest(
            task="convo_realtime_stt",
            model="nova-3",
            language="fi",
            keyterms=secret_terms,
        ),
    )

    # Verify the histogram observed the count, not the values.
    found_count = False
    for sample_family in m.STT_KEYTERMS_COUNT.collect():
        for s in sample_family.samples:
            if (
                s.name.endswith("_count")
                and s.labels.get("task") == "convo_realtime_stt"
                and s.labels.get("language") == "fi"
            ):
                assert s.value >= 1.0
                found_count = True
            for term in secret_terms:
                # Belt + suspenders: term values must NOT appear as labels.
                for v in s.labels.values():
                    assert term not in v
    assert found_count
