"""AnthropicChatProvider: fakes only, no network. The SDK client is a stub."""

from __future__ import annotations

import sys
import types as _pytypes
from types import SimpleNamespace

import pytest

from kielo_shared import llmroute
from kielo_shared.llm import spend_guard as sg
from kielo_shared.seam.llm import (
    AnthropicChatProvider,
    Error,
    ErrorClass,
    ProviderStopped,
    ProviderUnavailable,
    Request,
    claude_effort,
    strip_json_fence,
    with_metrics,
)
from kielo_shared.seam.llm import anthropic_provider

HAIKU = "claude-haiku-5-5"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("LLM_DAILY_BUDGET_USD", "0")
    monkeypatch.setenv("LLM_HOURLY_CALL_CAP", "0")
    llmroute.set_client_for_test(None)
    yield
    llmroute.set_client_for_test(None)


class _Recorder:
    def __init__(self):
        self.rows = []

    def record(self, family, model, **kw):
        self.rows.append((family, model, kw))


@pytest.fixture
def recorder(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(llmroute, "_recorder", rec)
    return rec


def _message(
    text="ok",
    stop="end_turn",
    tokens_in=1000,
    tokens_out=500,
    thinking=300,
    category=None,
):
    return SimpleNamespace(
        content=[
            SimpleNamespace(type="thinking", thinking=""),
            SimpleNamespace(type="text", text=text),
        ]
        if text
        else [SimpleNamespace(type="thinking", thinking="")],
        stop_reason=stop,
        stop_details=SimpleNamespace(category=category) if category else None,
        usage=SimpleNamespace(
            input_tokens=tokens_in,
            output_tokens=tokens_out,
            output_tokens_details=SimpleNamespace(thinking_tokens=thinking),
        ),
    )


class _Stream:
    def __init__(self, pieces, final, fail_after=False):
        self._pieces, self._final, self._fail_after = pieces, final, fail_after
        self.text_stream = self._texts()

    async def _texts(self):
        for piece in self._pieces:
            yield piece
        if self._fail_after:
            raise RuntimeError("stream broke")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_final_message(self):
        return self._final


class _Messages:
    def __init__(self, message=None, error=None, pieces=None, fail_after=False):
        self.message = message or _message()
        self.error = error
        self.pieces = pieces or ["o", "k"]
        self.fail_after = fail_after
        self.seen = []

    async def create(self, **kwargs):
        self.seen.append(kwargs)
        if self.error:
            raise self.error
        return self.message

    def stream(self, **kwargs):
        self.seen.append(kwargs)
        if self.error:
            raise self.error
        return _Stream(self.pieces, self.message, self.fail_after)


def _provider(messages=None, **kwargs):
    kwargs.setdefault("default_model", HAIKU)
    return AnthropicChatProvider(
        "k", client=SimpleNamespace(messages=messages or _Messages()), **kwargs
    )


def _req(**kwargs):
    kwargs.setdefault("prompt", "x")
    kwargs.setdefault("task", "t")
    return Request(**kwargs)


@pytest.mark.parametrize(
    "budget, effort",
    [
        (None, None),
        (-1, None),
        (0, "low"),
        (512, "low"),
        (1024, "low"),
        (1025, "medium"),
        (8192, "medium"),
    ],
)
def test_claude_effort_maps_a_thinking_budget(budget, effort):
    assert claude_effort(budget) == effort


@pytest.mark.asyncio
async def test_request_shape_and_effort():
    messages = _Messages()
    p = _provider(messages, thinking_budget=512)
    result = await p.generate(
        _req(prompt="hello", system_prompt="be brief", model="claude-sonnet-5-5")
    )
    assert result.raw_text == "ok"
    assert result.provider == f"anthropic-messages:{HAIKU}"
    (sent,) = messages.seen
    assert sent["model"] == "claude-sonnet-5-5"
    assert sent["messages"] == [{"role": "user", "content": "hello"}]
    assert sent["system"] == "be brief"
    assert sent["max_tokens"] == anthropic_provider.DEFAULT_MAX_TOKENS
    assert sent["output_config"] == {"effort": "low"}
    assert "thinking" not in sent and "stream" not in sent


@pytest.mark.asyncio
async def test_default_budget_leaves_effort_to_the_model():
    messages = _Messages()
    await _provider(messages).generate(_req())
    assert "output_config" not in messages.seen[0]
    assert "system" not in messages.seen[0]


@pytest.mark.asyncio
async def test_sampling_parameters_and_schema_are_never_sent():
    messages = _Messages()
    await _provider(messages).generate(
        _req(temperature=0.2, response_schema={"type": "object"})
    )
    sent = messages.seen[0]
    for name in ("temperature", "top_p", "top_k", "response_schema", "response_format"):
        assert name not in sent


@pytest.mark.asyncio
async def test_json_mime_asks_for_bare_json_and_strips_a_fence():
    messages = _Messages(message=_message(text='```json\n{"a": 1}\n```'))
    p = _provider(messages)
    result = await p.generate(
        _req(system_prompt="rules", response_mime_type="application/json")
    )
    assert result.raw_text == '{"a": 1}'
    assert messages.seen[0]["system"].startswith("rules\n\n")
    assert "JSON object" in messages.seen[0]["system"]

    bare = _Messages()
    await _provider(bare).generate(_req(response_mime_type="application/json"))
    assert bare.seen[0]["system"].startswith("Reply with a single JSON object")


@pytest.mark.parametrize(
    "raw, want",
    [
        ('```json\n{"a": 1}\n```', '{"a": 1}'),
        ('```\n{"a": 1}\n```', '{"a": 1}'),
        ('  ```json\n{"a": 1}\n```  ', '{"a": 1}'),
        ('{"a": 1}', '{"a": 1}'),
        ("plain ``` inside", "plain ``` inside"),
    ],
)
def test_strip_json_fence(raw, want):
    assert strip_json_fence(raw) == want


@pytest.mark.asyncio
async def test_an_empty_prompt_is_refused_before_any_call():
    messages = _Messages()
    with pytest.raises(Error) as ei:
        await _provider(messages).generate(_req(prompt=""))
    assert ei.value.error_class is ErrorClass.INVALID_REQUEST
    assert messages.seen == []


@pytest.mark.asyncio
async def test_no_model_is_refused():
    messages = _Messages()
    p = AnthropicChatProvider("k", client=SimpleNamespace(messages=messages))
    with pytest.raises(Error) as ei:
        await p.generate(_req())
    assert ei.value.error_class is ErrorClass.INVALID_REQUEST
    assert messages.seen == []


@pytest.mark.asyncio
async def test_usage_splits_thinking_out_of_output_and_reaches_the_sink():
    seen = []
    p = _provider(usage_sink=lambda *tokens: seen.append(tokens))
    await p.generate(_req())
    assert seen == [(1000, 200, 300)]


@pytest.mark.asyncio
async def test_family_records_usage_with_thinking_and_books_actual_spend(
    monkeypatch, recorder
):
    booked = []
    monkeypatch.setattr(
        anthropic_provider,
        "record_actual_usd",
        lambda usd, *, family="": booked.append((usd, family)),
    )
    p = _provider(family=llmroute.FAMILY_JUKA_FEEDBACK)
    await p.generate(_req())
    ((family, model, kw),) = recorder.rows
    assert (family, model) == (llmroute.FAMILY_JUKA_FEEDBACK, HAIKU)
    assert (kw["input_tokens"], kw["output_tokens"], kw["thinking_tokens"]) == (
        1000,
        200,
        300,
    )
    assert kw["usd"] == pytest.approx((1000 * 0.10 + 500 * 0.50) / 1e6)
    assert kw["error"] is False and kw["outcome"] == llmroute.OUTCOME_OK
    assert booked == [(kw["usd"], llmroute.FAMILY_JUKA_FEEDBACK)]


@pytest.mark.asyncio
async def test_no_family_records_nothing(recorder):
    await _provider().generate(_req())
    assert recorder.rows == []


@pytest.mark.asyncio
async def test_a_refusal_raises_is_booked_as_refused_and_still_reports_usage(
    recorder,
):
    seen = []
    p = _provider(
        _Messages(message=_message(text="", stop="refusal", category="cyber")),
        family="juka_feedback",
        usage_sink=lambda *tokens: seen.append(tokens),
    )
    with pytest.raises(Error) as ei:
        await p.generate(_req())
    assert ei.value.error_class is ErrorClass.PROVIDER_ERROR
    assert isinstance(ei.value.cause, ProviderStopped)
    assert ei.value.cause.reason == "refusal" and ei.value.cause.category == "cyber"
    assert seen == [(1000, 200, 300)]
    (row,) = recorder.rows
    assert row[2]["outcome"] == llmroute.OUTCOME_REFUSED
    assert row[2]["output_tokens"] == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("stop", ["max_tokens", "model_context_window_exceeded"])
async def test_a_cut_off_answer_raises_and_is_not_returned_as_text(recorder, stop):
    p = _provider(
        _Messages(message=_message(text='{"half":', stop=stop)), family="juka_feedback"
    )
    with pytest.raises(Error) as ei:
        await p.generate(_req())
    assert ei.value.error_class is ErrorClass.PROVIDER_ERROR
    assert ei.value.cause.reason == stop
    assert recorder.rows[0][2]["outcome"] == llmroute.OUTCOME_INVALID_OUTPUT


@pytest.mark.asyncio
async def test_a_message_with_no_text_is_an_empty_response(recorder):
    p = _provider(_Messages(message=_message(text="")), family="juka_feedback")
    with pytest.raises(Error) as ei:
        await p.generate(_req())
    assert ei.value.error_class is ErrorClass.EMPTY_RESPONSE
    assert recorder.rows[0][2]["outcome"] == llmroute.OUTCOME_INVALID_OUTPUT


class _Status(Exception):
    def __init__(self, status_code, message="boom"):
        super().__init__(message)
        self.status_code = status_code


class APITimeoutError(Exception):
    pass


class APIConnectionError(Exception):
    pass


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc, want",
    [
        (APITimeoutError("Request timed out."), ErrorClass.TIMEOUT),
        (APIConnectionError("Connection error."), ErrorClass.CONNECTION),
        (_Status(429), ErrorClass.SERVER_ERROR),
        (_Status(529, "overloaded"), ErrorClass.SERVER_ERROR),
        (_Status(500), ErrorClass.SERVER_ERROR),
        (_Status(401), ErrorClass.CLIENT_ERROR),
        (_Status(400), ErrorClass.CLIENT_ERROR),
        (RuntimeError("odd"), ErrorClass.PROVIDER_ERROR),
    ],
)
async def test_an_sdk_failure_is_classified_and_booked_as_an_error(recorder, exc, want):
    p = _provider(_Messages(error=exc), family="juka_feedback")
    with pytest.raises(Error) as ei:
        await p.generate(_req())
    assert ei.value.error_class is want
    assert ei.value.cause is exc
    ((_, _, kw),) = recorder.rows
    assert kw["error"] is True and kw["outcome"] == llmroute.OUTCOME_ERROR


@pytest.mark.asyncio
async def test_spend_guard_refuses_outside_production_and_makes_no_call(
    monkeypatch, recorder
):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("LLM_ALLOW_PAID_CALLS", raising=False)
    messages = _Messages()
    p = _provider(messages, family="juka_feedback")
    with pytest.raises(sg.PaidLLMCallRefused):
        await p.generate(_req())
    with pytest.raises(sg.PaidLLMCallRefused):
        _ = [c async for c in p.generate_stream(_req())]
    assert messages.seen == [] and recorder.rows == []


@pytest.mark.asyncio
async def test_spend_guard_admits_under_the_request_task_and_family(monkeypatch):
    admitted = []
    monkeypatch.setattr(
        anthropic_provider,
        "admit_paid_call",
        lambda task="", *, provider="", family="", **_: admitted.append(
            (task, provider, family)
        ),
    )
    await _provider(family="juka_feedback").generate(_req(task="convo_turn_feedback"))
    assert admitted == [
        ("convo_turn_feedback", f"anthropic-messages:{HAIKU}", "juka_feedback")
    ]


@pytest.mark.asyncio
async def test_an_unguarded_provider_leaves_admission_to_its_caller(monkeypatch):
    monkeypatch.setattr(
        anthropic_provider,
        "admit_paid_call",
        lambda *a, **k: pytest.fail("the caller admits this call"),
    )
    messages = _Messages()
    p = _provider(messages, guarded=False)
    await p.generate(_req())
    assert [c async for c in p.generate_stream(_req())] == ["o", "k"]
    assert len(messages.seen) == 2


class _Redis:
    def __init__(self):
        self.d = {}

    def incr(self, k):
        self.d[k] = int(self.d.get(k, 0)) + 1
        return self.d[k]

    def incrby(self, k, n):
        self.d[k] = int(self.d.get(k, 0)) + n
        return self.d[k]

    def expire(self, k, s):
        return True

    def mget(self, keys):
        return [self.d.get(k) for k in keys]


@pytest.mark.asyncio
async def test_the_family_daily_budget_counts_actual_spend_and_stops_a_call(
    monkeypatch,
):
    sg.set_redis_factory(_Redis)
    monkeypatch.setattr(sg, "_family_budget", lambda family: 0.001)
    monkeypatch.setenv("LLM_GUARD_EST_USD_PER_CALL", "0.002")
    try:
        messages = _Messages()
        p = _provider(messages, family="juka_feedback")
        for _ in range(3):
            await p.generate(_req())
        with pytest.raises(sg.LLMBudgetExceeded) as ei:
            await p.generate(_req())
        assert ei.value.reason == "family_daily_budget"
        assert len(messages.seen) == 3
    finally:
        sg.set_redis_factory(None)


@pytest.mark.asyncio
async def test_no_key_is_a_clear_unavailable_error_and_books_nothing(
    monkeypatch, recorder
):
    monkeypatch.setattr(
        anthropic_provider,
        "admit_paid_call",
        lambda *a, **k: pytest.fail("a call without a key must not be admitted"),
    )
    p = AnthropicChatProvider("", default_model=HAIKU, family="juka_feedback")
    with pytest.raises(ProviderUnavailable) as ei:
        await p.generate(_req())
    assert ei.value.error_class is ErrorClass.INVALID_REQUEST
    assert "key not configured" in str(ei.value)
    assert isinstance(ei.value, Error)
    with pytest.raises(ProviderUnavailable):
        _ = [c async for c in p.generate_stream(_req())]
    assert recorder.rows == []


@pytest.mark.asyncio
async def test_a_missing_sdk_is_unavailable_not_a_crash(monkeypatch):
    monkeypatch.setitem(sys.modules, "anthropic", None)
    p = AnthropicChatProvider("k", default_model=HAIKU)
    with pytest.raises(ProviderUnavailable) as ei:
        await p.generate(_req())
    assert "pip install kielo-shared[anthropic]" in str(ei.value)


@pytest.mark.asyncio
async def test_the_client_is_built_once_from_the_key(monkeypatch):
    built = []
    messages = _Messages()

    class _Async:
        def __init__(self, **kwargs):
            built.append(kwargs)
            self.messages = messages

    fake = _pytypes.ModuleType("anthropic")
    fake.AsyncAnthropic = _Async
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    p = AnthropicChatProvider(
        "sk-test", default_model=HAIKU, timeout=30.0, max_retries=0
    )
    await p.generate(_req())
    await p.generate(_req())
    assert built == [{"api_key": "sk-test", "timeout": 30.0, "max_retries": 0}]
    assert len(messages.seen) == 2


def _usage_lines(caplog):
    return [
        r.getMessage()
        for r in caplog.records
        if r.getMessage().startswith("LLM_USAGE ")
    ]


def _route(monkeypatch, route):
    seen = []

    def resolve(family, default, thinking=-1, provider="", key=None):
        seen.append((family, default, thinking, key))
        return route

    monkeypatch.setattr(llmroute, "resolve", resolve)
    return seen


@pytest.mark.asyncio
async def test_a_family_resolves_model_and_effort_through_the_route(
    monkeypatch, recorder, caplog
):
    seen = _route(
        monkeypatch,
        llmroute.Route(
            "claude-sonnet-5-5", 4096, 0.0, "anthropic", variant="candidate"
        ),
    )
    messages = _Messages()
    p = _provider(messages, family="juka_feedback", thinking_budget=512)
    with caplog.at_level("INFO", logger="kielo_shared.llmroute"):
        await p.generate(_req(metadata={"route_key": "session-1"}))
    assert seen == [("juka_feedback", HAIKU, 512, "session-1")]
    assert messages.seen[0]["model"] == "claude-sonnet-5-5"
    assert messages.seen[0]["output_config"] == {"effort": "medium"}
    ((_, model, kw),) = recorder.rows
    assert model == "claude-sonnet-5-5" and kw["fallback"] is False
    (line,) = _usage_lines(caplog)
    assert "variant=candidate" in line and "requested=claude-sonnet-5-5" in line


@pytest.mark.asyncio
async def test_a_refused_route_is_booked_as_a_fallback_with_the_requested_model(
    monkeypatch, recorder, caplog
):
    _route(
        monkeypatch,
        llmroute.Route(HAIKU, -1, 0.0, "anthropic", requested="claude-opus-5-5"),
    )
    with caplog.at_level("INFO", logger="kielo_shared.llmroute"):
        await _provider(family="juka_feedback").generate(_req())
    assert recorder.rows[0][2]["fallback"] is True
    (line,) = _usage_lines(caplog)
    assert f"model={HAIKU} requested=claude-opus-5-5" in line
    assert "fallback=1" in line


@pytest.mark.asyncio
async def test_a_route_to_another_provider_is_refused_without_a_call(
    monkeypatch, recorder
):
    _route(monkeypatch, llmroute.Route("gemini-3.8-flash", -1, 0.0, "google"))
    messages = _Messages()
    with pytest.raises(Error) as ei:
        await _provider(messages, family="juka_feedback").generate(_req())
    assert ei.value.error_class is ErrorClass.INVALID_REQUEST
    assert "only drives Claude" in str(ei.value)
    assert messages.seen == [] and recorder.rows == []


@pytest.mark.asyncio
async def test_stream_yields_text_and_reports_usage_once_at_the_end(recorder):
    seen = []
    p = _provider(
        _Messages(pieces=["a", "", "b"]),
        family="juka_feedback",
        usage_sink=lambda *tokens: seen.append(tokens),
    )
    chunks = [c async for c in p.generate_stream(_req())]
    assert chunks == ["a", "b"]
    assert seen == [(1000, 200, 300)]
    assert len(recorder.rows) == 1


@pytest.mark.asyncio
async def test_a_stream_that_ends_in_a_refusal_yields_its_text_then_raises(recorder):
    p = _provider(
        _Messages(pieces=["par"], message=_message(text="par", stop="refusal")),
        family="juka_feedback",
    )
    got = []
    with pytest.raises(Error) as ei:
        async for chunk in p.generate_stream(_req()):
            got.append(chunk)
    assert got == ["par"]
    assert ei.value.cause.reason == "refusal"
    assert recorder.rows[0][2]["outcome"] == llmroute.OUTCOME_REFUSED


@pytest.mark.asyncio
async def test_a_stream_cut_off_at_max_tokens_raises(recorder):
    p = _provider(
        _Messages(message=_message(text="par", stop="max_tokens")),
        family="juka_feedback",
    )
    with pytest.raises(Error) as ei:
        _ = [c async for c in p.generate_stream(_req())]
    assert ei.value.cause.reason == "max_tokens"


@pytest.mark.asyncio
async def test_a_stream_that_fails_to_open_books_one_error_call(recorder):
    p = _provider(_Messages(error=_Status(529, "overloaded")), family="juka_feedback")
    with pytest.raises(Error) as ei:
        _ = [c async for c in p.generate_stream(_req())]
    assert ei.value.error_class is ErrorClass.SERVER_ERROR
    assert len(recorder.rows) == 1 and recorder.rows[0][2]["error"] is True


@pytest.mark.asyncio
async def test_a_stream_that_breaks_midway_books_one_error_call(recorder):
    p = _provider(_Messages(pieces=["a"], fail_after=True), family="juka_feedback")
    got = []
    with pytest.raises(Error):
        async for chunk in p.generate_stream(_req()):
            got.append(chunk)
    assert got == ["a"]
    assert len(recorder.rows) == 1 and recorder.rows[0][2]["error"] is True


@pytest.mark.asyncio
async def test_with_metrics_passes_both_shapes_through():
    p = with_metrics(_provider())
    assert (await p.generate(_req())).raw_text == "ok"
    assert [c async for c in p.generate_stream(_req())] == ["o", "k"]
