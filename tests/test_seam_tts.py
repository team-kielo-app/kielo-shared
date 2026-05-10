"""Tests for `kielo_shared.seam.tts`.

Mirrors the Go-side `seam/tts/tts_test.go` so behavioral parity is
auditable. Provider unit tests cover transport classification + the
bounded ErrorClass mapping. Decorator tests cover the bounded label
contract on `kielo_tts_calls_total`.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from kielo_shared.seam.tts import (
    Error,
    ErrorClass,
    OpenAITTSProvider,
    Request,
    Result,
    class_of,
    with_metrics,
)


# ─────────────────────── provider unit tests ──────────────────────────


@pytest.mark.asyncio
async def test_openai_tts_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/v1/audio/speech")
        assert request.headers["Authorization"] == "Bearer test-key"
        return httpx.Response(200, content=b"\xff\xfb\x90mp3-bytes")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAITTSProvider("test-key", client, default_model="tts-1")
        res = await provider.synthesize(Request(
            text="hello",
            voice_id="alloy",
            speed=1.0,
            task="klearn_tts_baseword",
        ))

    assert isinstance(res, Result)
    assert res.audio.startswith(b"\xff\xfb\x90")
    assert res.provider == "openai-tts:tts-1"


@pytest.mark.asyncio
async def test_openai_tts_5xx_classified_server_error():
    transport = httpx.MockTransport(lambda _r: httpx.Response(500, text="overloaded"))
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAITTSProvider("k", client)
        with pytest.raises(Error) as ei:
            await provider.synthesize(Request(text="hi", voice_id="alloy", task="klearn_tts_baseword"))
    assert ei.value.error_class == ErrorClass.SERVER_ERROR


@pytest.mark.asyncio
async def test_openai_tts_4xx_classified_client_error():
    transport = httpx.MockTransport(lambda _r: httpx.Response(400, text="bad"))
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAITTSProvider("k", client)
        with pytest.raises(Error) as ei:
            await provider.synthesize(Request(text="hi", voice_id="alloy", task="klearn_tts_baseword"))
    assert ei.value.error_class == ErrorClass.CLIENT_ERROR


@pytest.mark.asyncio
async def test_openai_tts_timeout_classified():
    async def slow(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("simulated")

    transport = httpx.MockTransport(slow)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAITTSProvider("k", client)
        with pytest.raises(Error) as ei:
            await provider.synthesize(Request(text="hi", voice_id="alloy", task="klearn_tts_baseword"))
    assert ei.value.error_class == ErrorClass.TIMEOUT


@pytest.mark.asyncio
async def test_openai_tts_connection_error_classified():
    def boom(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns")

    transport = httpx.MockTransport(boom)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAITTSProvider("k", client)
        with pytest.raises(Error) as ei:
            await provider.synthesize(Request(text="hi", voice_id="alloy", task="klearn_tts_baseword"))
    assert ei.value.error_class == ErrorClass.CONNECTION


@pytest.mark.asyncio
async def test_openai_tts_empty_response_rejected():
    transport = httpx.MockTransport(lambda _r: httpx.Response(200, content=b""))
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAITTSProvider("k", client)
        with pytest.raises(Error) as ei:
            await provider.synthesize(Request(text="hi", voice_id="alloy", task="klearn_tts_baseword"))
    assert ei.value.error_class == ErrorClass.EMPTY_RESPONSE


@pytest.mark.asyncio
async def test_openai_tts_missing_api_key_rejected():
    provider = OpenAITTSProvider("", None)
    with pytest.raises(Error) as ei:
        await provider.synthesize(Request(text="hi", voice_id="alloy", task="klearn_tts_baseword"))
    assert ei.value.error_class == ErrorClass.CLIENT_ERROR


@pytest.mark.asyncio
async def test_openai_tts_empty_text_rejected():
    provider = OpenAITTSProvider("k", None)
    with pytest.raises(Error) as ei:
        await provider.synthesize(Request(text="", voice_id="alloy", task="klearn_tts_baseword"))
    assert ei.value.error_class == ErrorClass.CLIENT_ERROR


def test_class_of_handles_seam_and_unknown_errors():
    assert class_of(Error(ErrorClass.TIMEOUT)) == "timeout"
    assert class_of(RuntimeError("x")) == "unknown"
    assert class_of(None) == ""


# ─────────────────────── decorator integration ──────────────────────────


class _StubProvider:
    def __init__(self, result: Result | None = None, error: BaseException | None = None):
        self.result = result
        self.error = error
        self.last: Request | None = None

    async def synthesize(self, request: Request) -> Result:
        self.last = request
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result

    def provider_id(self, _request: Request) -> str:
        return "stub-tts:v0"


@pytest.mark.asyncio
async def test_decorator_passes_request_through_on_success():
    stub = _StubProvider(result=Result(audio=b"ok", provider="stub-tts:v0", latency_ms=1))
    dec = with_metrics(stub)
    res = await dec.synthesize(Request(text="hi", voice_id="alloy", task="klearn_tts_baseword"))
    assert res.audio == b"ok"
    assert stub.last is not None and stub.last.text == "hi"


@pytest.mark.asyncio
async def test_decorator_preserves_provider_error():
    stub = _StubProvider(error=Error(ErrorClass.SERVER_ERROR, RuntimeError("503")))
    dec = with_metrics(stub)
    with pytest.raises(Error) as ei:
        await dec.synthesize(Request(text="hi", voice_id="alloy", task="klearn_tts_baseword"))
    assert ei.value.error_class == ErrorClass.SERVER_ERROR


@pytest.mark.asyncio
async def test_decorator_increments_counter_with_bounded_labels():
    """Pin the bounded-cardinality contract for the metric family.
    The error label MUST come from the seam's ErrorClass enum, not
    from caller-supplied free text. We verify by running both a
    success and a server-error path and inspecting the registered
    Counter's label value set.
    """
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability import metrics as m

    # Cache hit: success path with empty error label.
    stub_ok = _StubProvider(result=Result(audio=b"ok", provider="stub-tts:v0", latency_ms=1))
    await with_metrics(stub_ok).synthesize(
        Request(text="x", voice_id="alloy", task="klearn_tts_baseword"),
    )

    stub_err = _StubProvider(error=Error(ErrorClass.SERVER_ERROR, RuntimeError("503")))
    with pytest.raises(Error):
        await with_metrics(stub_err).synthesize(
            Request(text="x", voice_id="alloy", task="klearn_tts_baseword"),
        )

    seen_errors: set[str] = set()
    for sample_family in m.TTS_CALLS_TOTAL.collect():
        for s in sample_family.samples:
            if s.name.endswith("_total") and s.labels.get("task") == "klearn_tts_baseword":
                seen_errors.add(s.labels.get("error", ""))
    assert "" in seen_errors, "success path should emit empty error label"
    assert "http_5xx" in seen_errors, "server error should emit bounded http_5xx label"


def test_decorator_does_not_block_event_loop():
    """Sanity: provider runs on the same loop the caller awaits on."""
    stub = _StubProvider(result=Result(audio=b"ok", provider="stub-tts:v0", latency_ms=0))
    asyncio.run(
        with_metrics(stub).synthesize(
            Request(text="hi", voice_id="alloy", task="klearn_tts_baseword"),
        )
    )


# ─────────────────────── streaming variant ──────────────────────────


@pytest.mark.asyncio
async def test_openai_tts_stream_yields_chunks_in_order():
    chunks_out = [b"\xff\xfb\x90", b"chunk-2", b"chunk-3"]

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"".join(chunks_out))

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAITTSProvider("k", client)
        collected: list[bytes] = []
        async for chunk in provider.synthesize_stream(
            Request(text="hi", voice_id="alloy", task="klearn_tts_baseword_streaming"),
        ):
            collected.append(chunk)
        # Order preserved (httpx may coalesce; assert concat equals upstream).
        assert b"".join(collected) == b"".join(chunks_out)


@pytest.mark.asyncio
async def test_openai_tts_stream_4xx_raises_seam_error_before_iteration():
    transport = httpx.MockTransport(lambda _r: httpx.Response(401, text="unauth"))
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAITTSProvider("k", client)
        with pytest.raises(Error) as ei:
            async for _ in provider.synthesize_stream(
                Request(text="hi", voice_id="alloy", task="klearn_tts_baseword_streaming"),
            ):
                pass
    assert ei.value.error_class == ErrorClass.CLIENT_ERROR


@pytest.mark.asyncio
async def test_openai_tts_stream_requires_caller_owned_http_client():
    """Streaming with an auto-spawned client would close the body
    mid-iteration. Provider rejects that path eagerly."""
    provider = OpenAITTSProvider("k", None)
    with pytest.raises(Error) as ei:
        async for _ in provider.synthesize_stream(
            Request(text="hi", voice_id="alloy", task="klearn_tts_baseword_streaming"),
        ):
            pass
    assert ei.value.error_class == ErrorClass.CLIENT_ERROR


class _StreamStubProvider:
    """Stub that exercises the decorator's streaming path without
    a real HTTP client."""

    def __init__(self, chunks: list[bytes] | None = None, error: BaseException | None = None):
        self._chunks = chunks or []
        self._error = error

    async def synthesize(self, _req: Request) -> Result:
        return Result(audio=b"unused", provider="stub", latency_ms=0)

    async def synthesize_stream(self, _req: Request):
        if self._error is not None:
            raise self._error
        for c in self._chunks:
            yield c

    def provider_id(self, _req: Request) -> str:
        return "stub-tts:stream"


@pytest.mark.asyncio
async def test_decorator_streams_chunks_and_increments_counter():
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability import metrics as m

    stub = _StreamStubProvider(chunks=[b"a", b"b", b"c"])
    dec = with_metrics(stub)

    out: list[bytes] = []
    async for chunk in dec.synthesize_stream(
        Request(text="hi", voice_id="alloy", task="klearn_tts_baseword_streaming"),
    ):
        out.append(chunk)
    assert out == [b"a", b"b", b"c"]

    seen_tasks: set[str] = set()
    for sample_family in m.TTS_CALLS_TOTAL.collect():
        for s in sample_family.samples:
            if s.name.endswith("_total"):
                seen_tasks.add(s.labels.get("task", ""))
    assert "klearn_tts_baseword_streaming" in seen_tasks


@pytest.mark.asyncio
async def test_decorator_emits_error_label_on_stream_failure():
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability import metrics as m

    stub = _StreamStubProvider(error=Error(ErrorClass.SERVER_ERROR, RuntimeError("503")))
    dec = with_metrics(stub)

    with pytest.raises(Error):
        async for _ in dec.synthesize_stream(
            Request(text="hi", voice_id="alloy", task="klearn_tts_paragraph_streaming"),
        ):
            pass

    seen_errors: set[str] = set()
    for sample_family in m.TTS_CALLS_TOTAL.collect():
        for s in sample_family.samples:
            if (
                s.name.endswith("_total")
                and s.labels.get("task") == "klearn_tts_paragraph_streaming"
            ):
                seen_errors.add(s.labels.get("error", ""))
    assert "http_5xx" in seen_errors


@pytest.mark.asyncio
async def test_decorator_streaming_raises_when_inner_lacks_streaming():
    """Decorator must not silently fall back to one-shot when caller
    asked for streaming — that would mask an unimplemented path."""
    stub_no_stream = _StubProvider(result=Result(audio=b"ok", provider="x", latency_ms=0))
    # Strip the streaming method to simulate a Provider without it.
    assert not hasattr(stub_no_stream, "synthesize_stream")
    dec = with_metrics(stub_no_stream)
    with pytest.raises(AttributeError):
        async for _ in dec.synthesize_stream(
            Request(text="hi", voice_id="alloy", task="klearn_tts_baseword_streaming"),
        ):
            pass
