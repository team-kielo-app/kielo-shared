"""Tests for `kielo_shared.seam.llm` (Python).

Mirrors `kielo-shared/seam/llm/llm_test.go` (Go side). Stubs the
`google.genai` client so the suite doesn't require the real SDK.
"""
from __future__ import annotations

import sys
import types as _pytypes

import pytest


# Inject a stub `google.genai.types` so the provider's
# `from google.genai import types` import resolves on a host
# that doesn't have the real SDK installed (engine container is
# the test harness; it doesn't ship google-genai).
#
# Care: if `google` already exists as a real namespace package
# (because `google.cloud.*` is installed), we attach our `genai`
# stub to it WITHOUT replacing the package. Replacing breaks
# parallel `from google.cloud import pubsub_v1` resolution in
# sibling tests.
def _install_stub_google_genai_types() -> None:
    if "google.genai" in sys.modules:
        return

    google_pkg = sys.modules.get("google")
    if google_pkg is None:
        google_pkg = _pytypes.ModuleType("google")
        google_pkg.__path__ = []  # type: ignore[attr-defined]
        sys.modules["google"] = google_pkg

    genai_mod = _pytypes.ModuleType("google.genai")
    genai_mod.__path__ = []  # type: ignore[attr-defined]

    types_mod = _pytypes.ModuleType("google.genai.types")

    class _GenerateContentConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    types_mod.GenerateContentConfig = _GenerateContentConfig  # type: ignore[attr-defined]
    genai_mod.types = types_mod  # type: ignore[attr-defined]

    sys.modules["google.genai"] = genai_mod
    sys.modules["google.genai.types"] = types_mod
    google_pkg.genai = genai_mod  # type: ignore[attr-defined]


_install_stub_google_genai_types()


from kielo_shared.seam.llm import (  # noqa: E402
    Error,
    ErrorClass,
    GeminiSDKProvider,
    OpenAIChatProvider,
    Request,
    Result,
    class_of,
    with_metrics,
)


class _FakeResponse:
    def __init__(self, text: str = "{\"ok\":1}"):
        self.text = text


class _FakeAsyncModels:
    def __init__(self, response_text: str = "{\"ok\":1}", error: BaseException | None = None):
        self._response_text = response_text
        self._error = error
        self.last_kwargs: dict | None = None

    async def generate_content(self, *, model, contents, config=None):
        self.last_kwargs = {"model": model, "contents": contents, "config": config}
        if self._error is not None:
            raise self._error
        return _FakeResponse(self._response_text)


class _FakeClient:
    def __init__(self, models: _FakeAsyncModels):
        self._models = models

    @property
    def aio(self):
        class _AIO:
            models = self._models  # noqa: F821 — closure
        return type("_AIO", (), {"models": self._models})()


@pytest.mark.asyncio
async def test_provider_passes_request_through():
    fake_models = _FakeAsyncModels(response_text='{"hint":"hei"}')
    client = _FakeClient(fake_models)

    p = GeminiSDKProvider("test-key", client=client, default_model="gemini-test")
    res = await p.generate(Request(
        prompt="give hint",
        task="convo_hint_engine",
        response_mime_type="application/json",
        temperature=0.7,
    ))
    assert isinstance(res, Result)
    assert res.raw_text == '{"hint":"hei"}'
    assert res.provider == "gemini-sdk:gemini-test"
    assert fake_models.last_kwargs["contents"] == "give hint"
    assert fake_models.last_kwargs["config"] is not None


@pytest.mark.asyncio
async def test_provider_rejects_empty_prompt():
    p = GeminiSDKProvider("k", client=_FakeClient(_FakeAsyncModels()))
    with pytest.raises(Error) as ei:
        await p.generate(Request(prompt="", task="t"))
    assert ei.value.error_class == ErrorClass.INVALID_REQUEST


@pytest.mark.asyncio
async def test_provider_classifies_timeout():
    err = TimeoutError("deadline exceeded")
    p = GeminiSDKProvider("k", client=_FakeClient(_FakeAsyncModels(error=err)))
    with pytest.raises(Error) as ei:
        await p.generate(Request(prompt="x", task="t"))
    assert ei.value.error_class == ErrorClass.TIMEOUT


@pytest.mark.asyncio
async def test_provider_classifies_unknown_provider_error():
    err = RuntimeError("plugin malfunction")
    p = GeminiSDKProvider("k", client=_FakeClient(_FakeAsyncModels(error=err)))
    with pytest.raises(Error) as ei:
        await p.generate(Request(prompt="x", task="t"))
    assert ei.value.error_class == ErrorClass.PROVIDER_ERROR


@pytest.mark.asyncio
async def test_provider_rejects_empty_response():
    p = GeminiSDKProvider("k", client=_FakeClient(_FakeAsyncModels(response_text="")))
    with pytest.raises(Error) as ei:
        await p.generate(Request(prompt="x", task="t"))
    assert ei.value.error_class == ErrorClass.EMPTY_RESPONSE


def test_class_of():
    assert class_of(Error(ErrorClass.TIMEOUT)) == "timeout"
    assert class_of(RuntimeError("x")) == "unknown"
    assert class_of(None) == ""


# ─────────────────── decorator integration ──────────────────────


class _StubProvider:
    def __init__(self, response: Result | None = None, error: BaseException | None = None):
        self._response = response or Result(raw_text="ok", provider="stub-llm:v0", latency_ms=0)
        self._error = error
        self.last: Request | None = None

    @property
    def provider_id(self) -> str:
        return "stub-llm:v0"

    async def generate(self, request: Request) -> Result:
        self.last = request
        if self._error is not None:
            raise self._error
        return self._response


@pytest.mark.asyncio
async def test_decorator_passthrough_success():
    stub = _StubProvider()
    dec = with_metrics(stub)
    res = await dec.generate(Request(prompt="hi", task="convo_hint_engine"))
    assert res.raw_text == "ok"
    assert stub.last is not None and stub.last.task == "convo_hint_engine"


@pytest.mark.asyncio
async def test_decorator_preserves_provider_error():
    stub = _StubProvider(error=Error(ErrorClass.SERVER_ERROR, RuntimeError("503")))
    dec = with_metrics(stub)
    with pytest.raises(Error) as ei:
        await dec.generate(Request(prompt="hi", task="convo_hint_engine"))
    assert ei.value.error_class == ErrorClass.SERVER_ERROR


@pytest.mark.asyncio
async def test_decorator_increments_shared_llm_calls_total():
    """Pin: Python seam emits via the SAME `kielo_llm_calls_total`
    family the engine-side `llm_emit` uses, with the same label
    set, so cross-process aggregation works."""
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability import metrics as m

    stub = _StubProvider()
    await with_metrics(stub).generate(
        Request(prompt="hi", task="convo_hint_engine"),
    )

    seen_tasks: set[str] = set()
    for sample_family in m.LLM_CALLS_TOTAL.collect():
        for s in sample_family.samples:
            if s.name.endswith("_total"):
                v = s.labels.get("task")
                if v:
                    seen_tasks.add(v)
    assert "convo_hint_engine" in seen_tasks


# ─────────────────── streaming variant ──────────────────────


class _StreamStubProvider:
    def __init__(self, chunks: list[str] | None = None, error: BaseException | None = None):
        self._chunks = chunks or []
        self._error = error

    @property
    def provider_id(self) -> str:
        return "stub-llm:stream"

    async def generate(self, _req: Request) -> Result:
        return Result(raw_text="unused", provider="stub-llm:stream", latency_ms=0)

    async def generate_stream(self, _req: Request):
        if self._error is not None:
            raise self._error
        for c in self._chunks:
            yield c


@pytest.mark.asyncio
async def test_provider_stream_yields_text_chunks():
    class _StreamFakeAsyncModels:
        async def generate_content_stream(self, *, model, contents, config=None):
            async def _gen():
                for t in ['{"a":', '"x"', "}"]:
                    yield _FakeResponse(t)

            return _gen()

    fake_models = _StreamFakeAsyncModels()

    class _StreamFakeClient:
        @property
        def aio(self):
            return type("_AIO", (), {"models": fake_models})()

    p = GeminiSDKProvider("k", client=_StreamFakeClient())
    chunks: list[str] = []
    async for chunk in p.generate_stream(Request(prompt="x", task="t")):
        chunks.append(chunk)
    assert "".join(chunks) == '{"a":"x"}'


@pytest.mark.asyncio
async def test_decorator_streams_chunks_and_increments_counter():
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability import metrics as m

    stub = _StreamStubProvider(chunks=["alpha", "beta", "gamma"])
    dec = with_metrics(stub)

    out: list[str] = []
    async for chunk in dec.generate_stream(
        Request(prompt="hi", task="convo_evaluation_stream"),
    ):
        out.append(chunk)
    assert out == ["alpha", "beta", "gamma"]

    seen_tasks: set[str] = set()
    for sample_family in m.LLM_CALLS_TOTAL.collect():
        for s in sample_family.samples:
            if s.name.endswith("_total"):
                v = s.labels.get("task")
                if v:
                    seen_tasks.add(v)
    assert "convo_evaluation_stream" in seen_tasks


@pytest.mark.asyncio
async def test_decorator_emits_error_label_on_stream_failure():
    pytest.importorskip("prometheus_client")
    from kielo_shared.observability import metrics as m

    stub = _StreamStubProvider(error=Error(ErrorClass.SERVER_ERROR, RuntimeError("503")))
    dec = with_metrics(stub)

    with pytest.raises(Error):
        async for _ in dec.generate_stream(
            Request(prompt="hi", task="convo_evaluation_stream_err"),
        ):
            pass

    seen_errors: set[str] = set()
    for sample_family in m.LLM_CALLS_TOTAL.collect():
        for s in sample_family.samples:
            if (
                s.name.endswith("_total")
                and s.labels.get("task") == "convo_evaluation_stream_err"
            ):
                seen_errors.add(s.labels.get("error", ""))
    assert "http_5xx" in seen_errors


@pytest.mark.asyncio
async def test_decorator_streaming_raises_when_inner_lacks_streaming():
    """Decorator must not silently fall back to one-shot when caller
    asked for streaming — that would mask an unimplemented path."""
    stub_no_stream = _StubProvider()
    # Strip the streaming method to simulate a Provider without it.
    assert not hasattr(stub_no_stream, "generate_stream")
    dec = with_metrics(stub_no_stream)
    with pytest.raises(AttributeError):
        async for _ in dec.generate_stream(
            Request(prompt="hi", task="convo_evaluation_stream"),
        ):
            pass


# ─────────────────── OpenAI chat provider ──────────────────────


class _FakeChatChoice:
    def __init__(self, content: str):
        class _Msg:
            pass

        m = _Msg()
        m.content = content
        self.message = m


class _FakeChatCompletion:
    def __init__(self, content: str):
        self.choices = [_FakeChatChoice(content)]


class _FakeChatDelta:
    def __init__(self, content: str | None):
        class _D:
            pass

        d = _D()
        d.content = content

        class _C:
            pass

        c = _C()
        c.delta = d
        self.choices = [c]


class _FakeChatStream:
    def __init__(self, tokens: list[str]):
        self._tokens = tokens

    def __aiter__(self):
        async def _gen():
            for t in self._tokens:
                yield _FakeChatDelta(t)

        return _gen()


class _FakeChatCompletions:
    def __init__(self, response_text: str = "{}", error: BaseException | None = None, stream_tokens: list[str] | None = None):
        self._response_text = response_text
        self._error = error
        self._stream_tokens = stream_tokens or []
        self.last_kwargs: dict | None = None

    async def create(self, **kwargs):
        self.last_kwargs = kwargs
        if self._error is not None:
            raise self._error
        if kwargs.get("stream"):
            return _FakeChatStream(self._stream_tokens)
        return _FakeChatCompletion(self._response_text)


class _FakeChatClient:
    def __init__(self, completions: _FakeChatCompletions):
        self.chat = type("_Chat", (), {"completions": completions})()


@pytest.mark.asyncio
async def test_openai_chat_provider_passes_request_through():
    completions = _FakeChatCompletions(response_text='{"matched_step":1}')
    client = _FakeChatClient(completions)
    p = OpenAIChatProvider(client, default_model="gpt-4o-mini")

    res = await p.generate(Request(
        prompt="user prompt",
        system_prompt="system instr",
        task="convo_step_evaluate_user",
        response_mime_type="application/json",
        temperature=0.2,
    ))
    assert res.raw_text == '{"matched_step":1}'
    assert res.provider == "openai-chat:gpt-4o-mini"
    msgs = completions.last_kwargs["messages"]
    assert msgs == [
        {"role": "system", "content": "system instr"},
        {"role": "user", "content": "user prompt"},
    ]
    assert completions.last_kwargs["response_format"] == {"type": "json_object"}
    assert completions.last_kwargs["temperature"] == 0.2


@pytest.mark.asyncio
async def test_openai_chat_provider_rejects_empty_prompt():
    p = OpenAIChatProvider(_FakeChatClient(_FakeChatCompletions()))
    with pytest.raises(Error) as ei:
        await p.generate(Request(prompt="", task="t"))
    assert ei.value.error_class == ErrorClass.INVALID_REQUEST


@pytest.mark.asyncio
async def test_openai_chat_provider_classifies_timeout():
    err = TimeoutError("request timeout")
    p = OpenAIChatProvider(_FakeChatClient(_FakeChatCompletions(error=err)))
    with pytest.raises(Error) as ei:
        await p.generate(Request(prompt="x", task="t"))
    assert ei.value.error_class == ErrorClass.TIMEOUT


@pytest.mark.asyncio
async def test_openai_chat_provider_streams_delta_tokens():
    completions = _FakeChatCompletions(stream_tokens=['{"ok"', ":", "1}"])
    client = _FakeChatClient(completions)
    p = OpenAIChatProvider(client, default_model="gpt-4o-mini")

    out: list[str] = []
    async for token in p.generate_stream(Request(prompt="x", task="t", response_mime_type="application/json")):
        out.append(token)
    assert "".join(out) == '{"ok":1}'
    assert completions.last_kwargs["stream"] is True


@pytest.mark.asyncio
async def test_openai_chat_provider_rejects_missing_client():
    p = OpenAIChatProvider(None)
    with pytest.raises(Error) as ei:
        await p.generate(Request(prompt="x", task="t"))
    assert ei.value.error_class == ErrorClass.INVALID_REQUEST
