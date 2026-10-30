"""GeminiSDKProvider under the AI-models control plane: fakes only, no network."""

from __future__ import annotations

import sys
import types as _pytypes
from types import SimpleNamespace

import pytest

from kielo_shared import llmroute
from kielo_shared.llm import spend_guard as sg
from kielo_shared.seam.llm import Error, GeminiSDKProvider, Request


class _Cfg:
    def __init__(self, **kw):
        self.kwargs = kw
        self.thinking_config = None


class _Think:
    def __init__(self, thinking_budget):
        self.thinking_budget = thinking_budget


@pytest.fixture(autouse=True)
def genai_stub(monkeypatch):
    google = sys.modules.setdefault("google", _pytypes.ModuleType("google"))
    if not hasattr(google, "__path__"):
        google.__path__ = []
    genai = sys.modules.setdefault("google.genai", _pytypes.ModuleType("google.genai"))
    genai.__path__ = []
    types_mod = _pytypes.ModuleType("google.genai.types")
    types_mod.GenerateContentConfig = _Cfg
    types_mod.ThinkingConfig = _Think
    monkeypatch.setitem(sys.modules, "google.genai.types", types_mod)
    monkeypatch.setattr(genai, "types", types_mod, raising=False)
    monkeypatch.setattr(google, "genai", genai, raising=False)
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("LLM_DAILY_BUDGET_USD", "0")
    monkeypatch.setenv("LLM_HOURLY_CALL_CAP", "0")


class _Recorder:
    def __init__(self):
        self.rows = []

    def record(self, family, model, **kw):
        self.rows.append((family, model, kw))


class _Models:
    def __init__(self, error=None):
        self.error = error
        self.seen = []

    async def generate_content(self, *, model, contents, config=None):
        self.seen.append((model, config))
        if self.error:
            raise self.error
        return SimpleNamespace(
            text="ok",
            usage_metadata=SimpleNamespace(
                prompt_token_count=1000,
                candidates_token_count=200,
                thoughts_token_count=300,
            ),
        )

    async def generate_content_stream(self, *, model, contents, config=None):
        async def gen():
            yield SimpleNamespace(text="a", usage_metadata=None)
            yield SimpleNamespace(
                text="b",
                usage_metadata=SimpleNamespace(
                    prompt_token_count=10, candidates_token_count=5, thoughts_token_count=0
                ),
            )

        return gen()


def _client(models):
    return SimpleNamespace(aio=SimpleNamespace(models=models))


def _route(monkeypatch, model, thinking):
    monkeypatch.setattr(
        llmroute, "resolve",
        lambda family, default, dt=-1: llmroute.Route(model, thinking, 0.0),
    )


@pytest.fixture
def recorder(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(llmroute, "_recorder", rec)
    return rec


@pytest.mark.asyncio
async def test_family_routes_model_thinking_and_records_usage(monkeypatch, recorder):
    _route(monkeypatch, "gemini-3.8-flash", 0)
    models = _Models()
    p = GeminiSDKProvider("k", client=_client(models), family=llmroute.FAMILY_KTV_AI)
    await p.generate(Request(prompt="x", task="t", model="gemini-old"))
    model, cfg = models.seen[0]
    assert model == "gemini-3.8-flash"
    assert cfg.thinking_config.thinking_budget == 0
    family, rmodel, kw = recorder.rows[0]
    assert (family, rmodel) == (llmroute.FAMILY_KTV_AI, "gemini-3.8-flash")
    assert (kw["input_tokens"], kw["output_tokens"], kw["thinking_tokens"]) == (1000, 200, 300)
    assert kw["usd"] == pytest.approx((1000 * 0.75 + 500 * 3.75) / 1e6)
    assert kw["error"] is False


@pytest.mark.asyncio
async def test_no_family_leaves_behaviour_and_records_nothing(recorder):
    models = _Models()
    p = GeminiSDKProvider("k", client=_client(models), default_model="gemini-x")
    await p.generate(Request(prompt="x", task="t"))
    assert models.seen[0][0] == "gemini-x"
    assert models.seen[0][1] is None
    assert recorder.rows == []


@pytest.mark.asyncio
async def test_failed_call_records_error(monkeypatch, recorder):
    _route(monkeypatch, "gemini-3.8-flash", -1)
    p = GeminiSDKProvider(
        "k", client=_client(_Models(error=RuntimeError("boom"))), family="ktv_ai"
    )
    with pytest.raises(Error):
        await p.generate(Request(prompt="x", task="t"))
    assert recorder.rows[0][2]["error"] is True


@pytest.mark.asyncio
async def test_stream_records_last_usage(monkeypatch, recorder):
    _route(monkeypatch, "gemini-3.8-flash", -1)
    p = GeminiSDKProvider("k", client=_client(_Models()), family="ktv_ai")
    chunks = [c async for c in p.generate_stream(Request(prompt="x", task="t"))]
    assert chunks == ["a", "b"]
    assert recorder.rows[0][2]["input_tokens"] == 10


@pytest.mark.asyncio
async def test_guard_refusal_is_deterministic_and_makes_no_call(monkeypatch, recorder):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("LLM_ALLOW_PAID_CALLS", raising=False)
    models = _Models()
    p = GeminiSDKProvider("k", client=_client(models), family="ktv_ai")
    with pytest.raises(sg.PaidLLMCallRefused):
        await p.generate(Request(prompt="x", task="t"))
    assert models.seen == [] and recorder.rows == []


def _call_lines(caplog):
    return [
        r.getMessage() for r in caplog.records if r.getMessage().startswith("LLM_CALL ")
    ]


@pytest.mark.asyncio
async def test_the_call_records_its_variant_outcome_and_no_fallback(
    monkeypatch, recorder, caplog
):
    monkeypatch.setattr(
        llmroute,
        "resolve",
        lambda family, default, dt=-1, **kw: llmroute.Route(
            "claude-haiku-5-5", -1, 0.0, "anthropic", variant="candidate"
        ),
    )
    p = GeminiSDKProvider("k", client=_client(_Models()), family="scene_pack")
    with caplog.at_level("INFO", logger="kielo_shared.llmroute"):
        await p.generate(Request(prompt="x", task="t"))
    kw = recorder.rows[0][2]
    assert (kw["outcome"], kw["fallback"]) == ("ok", False)
    (line,) = _call_lines(caplog)
    assert (
        "family=scene_pack model=claude-haiku-5-5 provider=anthropic variant=candidate"
        in line
    )
    assert "outcome=ok fallback=0" in line


@pytest.mark.asyncio
async def test_a_refused_route_records_the_default_run_as_a_fallback(
    monkeypatch, recorder, caplog
):
    monkeypatch.setattr(
        llmroute,
        "resolve",
        lambda family, default, dt=-1, **kw: llmroute.Route(
            "gemini-default", -1, 0.0, "google", requested="claude-haiku-5-5"
        ),
    )
    p = GeminiSDKProvider("k", client=_client(_Models()), family="scene_pack")
    with caplog.at_level("INFO", logger="kielo_shared.llmroute"):
        await p.generate(Request(prompt="x", task="t"))
    _, model, kw = recorder.rows[0]
    assert (model, kw["fallback"]) == ("gemini-default", True)
    (line,) = _call_lines(caplog)
    assert "variant=route" in line and line.endswith("fallback=1")


@pytest.mark.asyncio
async def test_a_failed_call_records_the_error_outcome(monkeypatch, recorder):
    _route(monkeypatch, "gemini-3.8-flash", -1)
    p = GeminiSDKProvider(
        "k", client=_client(_Models(error=RuntimeError("boom"))), family="ktv_ai"
    )
    with pytest.raises(Error):
        await p.generate(Request(prompt="x", task="t"))
    assert recorder.rows[0][2]["outcome"] == "error"


@pytest.mark.asyncio
async def test_an_empty_answer_is_an_invalid_output_that_still_books_usage(
    monkeypatch, recorder
):
    _route(monkeypatch, "gemini-3.8-flash", -1)

    class _Empty(_Models):
        async def generate_content(self, *, model, contents, config=None):
            response = await super().generate_content(
                model=model, contents=contents, config=config
            )
            response.text = ""
            return response

    p = GeminiSDKProvider("k", client=_client(_Empty()), family="ktv_ai")
    with pytest.raises(Error):
        await p.generate(Request(prompt="x", task="t"))
    kw = recorder.rows[0][2]
    assert (kw["outcome"], kw["error"], kw["input_tokens"]) == (
        "invalid_output",
        False,
        1000,
    )


@pytest.mark.asyncio
async def test_a_route_key_in_the_request_metadata_reaches_resolve(
    monkeypatch, recorder
):
    seen = []

    def fake_resolve(family, default, dt=-1, **kw):
        seen.append(kw)
        return llmroute.Route("gemini-3.8-flash", -1, 0.0)

    monkeypatch.setattr(llmroute, "resolve", fake_resolve)
    p = GeminiSDKProvider("k", client=_client(_Models()), family="scene_pack")
    await p.generate(Request(prompt="x", task="t", metadata={"route_key": "deck-7"}))
    await p.generate(Request(prompt="x", task="t"))
    assert seen == [{"key": "deck-7"}, {}]
