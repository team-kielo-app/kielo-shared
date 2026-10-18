"""Control-plane resolver: 30s cache, fail-open, usage rollup, per-family budget."""

from __future__ import annotations

import httpx
import pytest

from kielo_shared import llmroute
from kielo_shared.llm import spend_guard as sg


class _Resp:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


def _body(model="gemini-3.8-flash", thinking=0, budget=None):
    return {
        "items": [
            {
                "family": "juka_hints",
                "model": model,
                "thinking_budget": thinking,
                "daily_budget_usd": budget,
            }
        ]
    }


def test_resolve_follows_store_after_ttl(monkeypatch):
    now = [100.0]
    state = {"body": _body(budget=1.5), "hits": 0}

    def fake_get(url, headers=None, timeout=None):
        state["hits"] += 1
        return _Resp(state["body"])

    monkeypatch.setattr(httpx, "get", fake_get)
    client = llmroute.RouteClient("http://loc", "k", ttl=30, clock=lambda: now[0])
    first = client.resolve("juka_hints", "compiled")
    assert (first.model, first.thinking_budget, first.daily_budget_usd) == (
        "gemini-3.8-flash",
        0,
        1.5,
    )
    state["body"] = _body(model="gemini-3.5-flash", thinking=-1)
    assert client.resolve("juka_hints", "compiled").model == "gemini-3.8-flash"
    now[0] += 31
    client.resolve("juka_hints", "compiled")  # triggers background refresh
    for t in __import__("threading").enumerate():
        if t is not __import__("threading").current_thread() and t.daemon:
            t.join(timeout=2)
    assert client.resolve("juka_hints", "compiled").model == "gemini-3.5-flash"
    assert client.resolve("nope", "compiled").model == "compiled"


def test_fail_open(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "get", boom)
    assert llmroute.RouteClient("http://loc").resolve("x", "compiled", 7) == llmroute.Route(
        "compiled", 7, 0.0
    )
    assert llmroute.RouteClient("").resolve("x", "compiled").model == "compiled"
    llmroute.set_client_for_test(None)
    assert llmroute.resolve("x", "compiled").model == "compiled"


def test_recorder_aggregates_and_flushes(monkeypatch):
    posted = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        posted["url"], posted["json"] = url, json
        return _Resp({})

    monkeypatch.setattr(httpx, "post", fake_post)
    rec = llmroute.UsageRecorder("svc", "http://loc", "k", flush_seconds=3600, clock=lambda: 7200.0 + 5)
    monkeypatch.setattr(rec, "_ensure_thread", lambda: None)
    for i in range(1, 101):
        rec.record(
            "juka_hints", "m", input_tokens=10, output_tokens=5, thinking_tokens=2,
            usd=0.001, latency_ms=i, error=(i % 50 == 0), retries=1,
        )
    assert rec.flush() is True
    (row,) = posted["json"]["rows"]
    assert posted["url"].endswith("/llm-usage")
    assert (row["calls"], row["errors"], row["retries"], row["input_tokens"]) == (100, 2, 100, 1000)
    assert (row["latency_ms_p50"], row["latency_ms_p95"]) == (50, 95)
    assert row["hour"] == "1970-01-01T02:00:00Z"
    assert llmroute.UsageRecorder("svc", "").enabled is False


def test_failed_flush_keeps_counts(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "post", boom)
    rec = llmroute.UsageRecorder("svc", "http://loc", clock=lambda: 3600.0)
    monkeypatch.setattr(rec, "_ensure_thread", lambda: None)
    rec.record("f", "m", usd=0.5)
    assert rec.flush() is False
    assert rec.drain()[0]["usd"] == 0.5


class _FakeRedis:
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


def test_spend_guard_honours_family_budget(monkeypatch):
    for k in ("ENVIRONMENT", "K_SERVICE", "LLM_DAILY_BUDGET_USD", "LLM_HOURLY_CALL_CAP"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_ALLOW_PAID_CALLS", "true")
    monkeypatch.setenv("LLM_GUARD_EST_USD_PER_CALL", "0.01")
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _Resp(_body(budget=0.02)))
    llmroute.set_client_for_test(llmroute.RouteClient("http://loc"))
    sg.set_clock(lambda: 1_000_000.0)
    sg.set_redis_factory(_FakeRedis)
    try:
        sg.admit_paid_call("t", family="juka_hints")
        sg.record_actual_usd(0.03, family="juka_hints")
        with pytest.raises(sg.LLMBudgetExceeded) as exc:
            sg.admit_paid_call("t", family="juka_hints")
        assert exc.value.reason == "family_daily_budget"
        sg.admit_paid_call("t", family="other_family")
        token = sg.llm_family_var.set("juka_hints")
        try:
            with pytest.raises(sg.LLMBudgetExceeded):
                sg.admit_paid_call("t")
        finally:
            sg.llm_family_var.reset(token)
    finally:
        sg.set_redis_factory(None)
        sg.set_clock(None)
        llmroute.set_client_for_test(None)


def _fake_store(routes, models):
    def fake_get(url, headers=None, timeout=None):
        return _Resp(models if url.endswith("/llm-models") else routes)

    return fake_get


def test_route_resolves_provider_from_llm_models(monkeypatch):
    routes = {"items": [{"family": "juka_live", "model": "m-open", "thinking_budget": -1}]}
    models = {
        "items": [
            {"model": "m-open", "provider": "openai", "input_usd_per_mtok": 2.5, "output_usd_per_mtok": 10},
            {"model": "m-goog", "provider": "google", "input_usd_per_mtok": 0.25, "output_usd_per_mtok": 1.5},
        ]
    }
    monkeypatch.setattr(httpx, "get", _fake_store(routes, models))
    client = llmroute.RouteClient("http://loc")
    got = client.resolve("juka_live", "compiled")
    assert (got.model, got.provider) == ("m-open", "openai")
    llmroute.set_client_for_test(client)
    try:
        assert llmroute.model_price("m-goog") == (0.25, 1.5)
        assert llmroute.estimate_usd("m-open", 1_000_000, 0, 0) == 2.5
    finally:
        llmroute.set_client_for_test(None)


def test_route_provider_falls_back_to_name_family_when_model_unlisted(monkeypatch):
    routes = {"items": [{"family": "juka_live", "model": "gemini-x", "thinking_budget": -1}]}
    monkeypatch.setattr(httpx, "get", _fake_store(routes, {"items": []}))
    client = llmroute.RouteClient("http://loc")
    assert client.resolve("juka_live", "compiled").provider == "google"


def test_route_row_provider_is_honoured_when_models_unreachable(monkeypatch):
    routes = {"items": [{"family": "juka_live", "model": "odd", "provider": "openai"}]}

    def fake_get(url, headers=None, timeout=None):
        if url.endswith("/llm-models"):
            raise httpx.ConnectError("down")
        return _Resp(routes)

    monkeypatch.setattr(httpx, "get", fake_get)
    assert llmroute.RouteClient("http://loc").resolve("juka_live", "c").provider == "openai"


def test_default_route_carries_the_default_provider():
    llmroute.set_client_for_test(None)
    assert llmroute.resolve("x", "gemini-z").provider == "google"
    assert llmroute.resolve("x", "anything", default_provider="openai").provider == "openai"
