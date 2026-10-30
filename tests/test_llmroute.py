"""Control-plane resolver: 30s cache, fail-open, usage rollup, per-family budget."""

from __future__ import annotations

import time

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


def _models(*names, provider="google", active=True):
    return {
        "items": [
            {
                "model": n,
                "provider": provider,
                "input_usd_per_mtok": 1,
                "output_usd_per_mtok": 2,
                "active": active,
            }
            for n in names
        ]
    }


def test_resolve_follows_store_after_ttl(monkeypatch):
    now = [100.0]
    state = {"body": _body(budget=1.5), "hits": 0}

    def fake_get(url, headers=None, timeout=None):
        state["hits"] += 1
        if url.endswith("/llm-models"):
            return _Resp(_models("gemini-3.8-flash", "gemini-3.5-flash"))
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
    monkeypatch.setattr(
            httpx,
            "get",
            lambda url, *a, **k: _Resp(
                _models("gemini-3.8-flash")
                if url.endswith("/llm-models")
                else _body(budget=0.02)
            ),
        )
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


def _models_down(routes):
    def fake_get(url, headers=None, timeout=None):
        if url.endswith("/llm-models"):
            raise httpx.ConnectError("down")
        return _Resp(routes)

    return fake_get


def test_provider_is_inferred_only_while_models_never_loaded(monkeypatch):
    routes = {"items": [{"family": "juka_live", "model": "gemini-x", "thinking_budget": -1}]}
    monkeypatch.setattr(httpx, "get", _models_down(routes))
    client = llmroute.RouteClient("http://loc")
    assert client.resolve("juka_live", "compiled").provider == "google"
    assert client.route("juka_live").model == "gemini-x"


def test_loaded_models_table_without_the_model_refuses_the_route(monkeypatch, caplog):
    routes = {"items": [{"family": "juka_live", "model": "gemini-x"}]}
    monkeypatch.setattr(httpx, "get", _fake_store(routes, _models("other")))
    client = llmroute.RouteClient("http://loc")
    with caplog.at_level("ERROR"):
        for _ in range(3):
            assert client.route("juka_live") is None
    assert client.resolve("juka_live", "compiled").model == "compiled"
    assert caplog.text.count("missing from llm_models") == 1


def test_inactive_model_refuses_the_route(monkeypatch):
    routes = {"items": [{"family": "juka_live", "model": "m1"}]}
    monkeypatch.setattr(
        httpx, "get", _fake_store(routes, _models("m1", active=False))
    )
    assert llmroute.RouteClient("http://loc").route("juka_live") is None


def test_a_family_outside_the_openai_allowlist_refuses_an_openai_route(monkeypatch):
    routes = {"items": [{"family": "juka_hints", "model": "o1"}, {"family": "juka_live", "model": "o1"}]}
    monkeypatch.setattr(
        httpx, "get", _fake_store(routes, _models("o1", provider="openai"))
    )
    client = llmroute.RouteClient("http://loc")
    assert client.route("juka_hints") is None
    assert client.route("juka_live").provider == "openai"


class _Snapshots:
    def __init__(self):
        self.saved = None

    def load(self):
        return self.saved

    def save(self, snap):
        self.saved = snap


def test_last_good_snapshot_serves_a_cold_start_during_an_outage(monkeypatch):
    routes = {"items": [{"family": "juka_live", "model": "m1", "thinking_budget": -1}]}
    store = _Snapshots()
    monkeypatch.setattr(httpx, "get", _fake_store(routes, _models("m1", provider="openai")))
    first = llmroute.RouteClient("http://loc")
    first.set_snapshot_store(store.load, store.save)
    first.warm()
    assert store.saved is not None

    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "get", boom)
    cold = llmroute.RouteClient("http://loc")
    cold.set_snapshot_store(store.load, store.save)
    cold.warm()
    got = cold.route("juka_live")
    assert (got.model, got.provider) == ("m1", "openai")


def test_routes_up_models_down_at_cold_start_then_models_arrive(monkeypatch):
    routes = {"items": [{"family": "juka_live", "model": "gemini-x"}]}
    monkeypatch.setattr(httpx, "get", _models_down(routes))
    client = llmroute.RouteClient("http://loc", ttl=1, clock=iter(range(0, 1000, 5)).__next__)
    client.warm()
    assert client.route("juka_live").provider == "google"
    monkeypatch.setattr(httpx, "get", _fake_store(routes, _models("gemini-x")))
    client.warm()
    assert client.route("juka_live").provider == "google"


def test_cold_start_on_the_event_loop_does_not_fetch(monkeypatch):
    import asyncio

    calls = []

    def fake_get(*a, **k):
        calls.append(a)
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "get", fake_get)
    client = llmroute.RouteClient("http://loc")

    async def go():
        return client.route("juka_live")

    assert asyncio.run(go()) is None
    for t in __import__("threading").enumerate():
        if t.daemon and t is not __import__("threading").current_thread():
            t.join(timeout=2)


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


def test_stored_route_is_none_without_a_row(monkeypatch):
    routes = {"items": [{"family": "juka_live", "model": "gemini-x"}]}
    monkeypatch.setattr(httpx, "get", _models_down(routes))
    llmroute.set_client_for_test(llmroute.RouteClient("http://loc"))
    try:
        assert llmroute.stored_route("juka_live").model == "gemini-x"
        assert llmroute.stored_route("nope") is None
    finally:
        llmroute.set_client_for_test(None)
    assert llmroute.stored_route("juka_live") is None


def test_headroom_is_read_only_and_record_usd_books_the_full_cost(monkeypatch):
    for k in ("ENVIRONMENT", "K_SERVICE", "LLM_DAILY_BUDGET_USD", "LLM_HOURLY_CALL_CAP"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_ALLOW_PAID_CALLS", "true")
    monkeypatch.setattr(
        httpx,
        "get",
        _fake_store(_body(model="gemini-3.8-flash", budget=0.05), _models("gemini-3.8-flash")),
    )
    redis = _FakeRedis()
    llmroute.set_client_for_test(llmroute.RouteClient("http://loc"))
    sg.set_clock(lambda: 1_000_000.0)
    sg.set_redis_factory(lambda: redis)
    try:
        assert sg.has_headroom("juka_hints") is True
        assert redis.d == {}
        sg.record_usd(0.03, family="juka_hints")
        assert sg.has_headroom("juka_hints") is True
        sg.record_usd(0.03, family="juka_hints")
        assert sg.has_headroom("juka_hints") is False
        assert sg.has_headroom("other_family") is True
    finally:
        sg.set_redis_factory(None)
        sg.set_clock(None)
        llmroute.set_client_for_test(None)


def test_headroom_false_when_paid_calls_are_disabled(monkeypatch):
    for k in ("ENVIRONMENT", "K_SERVICE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_ALLOW_PAID_CALLS", "false")
    assert sg.has_headroom("juka_live") is False


def test_snapshot_json_store_round_trips():
    class _R:
        def __init__(self):
            self.d = {}

        def get(self, k):
            return self.d.get(k)

        def set(self, k, v, ex=None):
            self.d[k] = v

    load, save = llmroute.snapshot_json_store(_R(), "k")
    assert load() is None
    save({"routes": {"items": []}})
    assert load() == {"routes": {"items": []}}


def test_an_empty_models_table_does_not_refuse_every_route(monkeypatch):
    routes = {"items": [{"family": "juka_live", "model": "gemini-x"}]}
    monkeypatch.setattr(httpx, "get", _fake_store(routes, {"items": []}))
    got = llmroute.RouteClient("http://loc").route("juka_live")
    assert got is not None and got.provider == "google"


def test_every_unlisted_family_is_gemini_only_by_default(monkeypatch):
    routes = {"items": [{"family": f, "model": "o1"} for f in ("exercise_judge", "web_ingest", "brand_new", "juka_feedback")]}
    monkeypatch.setattr(httpx, "get", _fake_store(routes, _models("o1", provider="openai")))
    client = llmroute.RouteClient("http://loc")
    for family in ("exercise_judge", "web_ingest", "brand_new"):
        assert client.route(family) is None
    assert client.route("juka_feedback").provider == "openai"


def test_refresh_if_stale_refreshes_only_old_tables(monkeypatch):
    import asyncio

    calls = []
    routes = {"items": [{"family": "juka_live", "model": "gemini-x"}]}

    def fake_get(url, headers=None, timeout=None):
        calls.append(url)
        return _Resp(_models("gemini-x") if url.endswith("/llm-models") else routes)

    monkeypatch.setattr(httpx, "get", fake_get)
    now = [1000.0]
    client = llmroute.RouteClient("http://loc", clock=lambda: now[0])
    llmroute.set_client_for_test(client)
    try:
        client.warm()
        n = len(calls)
        asyncio.run(llmroute.refresh_if_stale(300))
        assert len(calls) == n
        now[0] += 301
        asyncio.run(llmroute.refresh_if_stale(300))
        assert len(calls) > n
    finally:
        llmroute.set_client_for_test(None)


def test_the_global_ceiling_is_told_apart_from_a_family_cap(monkeypatch):
    for k in ("ENVIRONMENT", "K_SERVICE", "LLM_HOURLY_CALL_CAP"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_ALLOW_PAID_CALLS", "true")
    monkeypatch.setenv("LLM_DAILY_BUDGET_USD", "1")
    body = {"items": [{"family": "juka_live", "model": "gemini-x", "daily_budget_usd": 0.5}]}
    models = {"items": [{"model": "gemini-x", "provider": "google", "active": True}]}
    monkeypatch.setattr(
        httpx,
        "get",
        lambda url, *a, **k: _Resp(models if url.endswith("/llm-models") else body),
    )
    redis = _FakeRedis()
    llmroute.set_client_for_test(llmroute.RouteClient("http://loc"))
    sg.set_clock(lambda: 1_000_000.0)
    sg.set_redis_factory(lambda: redis)
    try:
        assert sg.session_headroom("juka_live") == sg.HEADROOM_OK
        redis.d[sg._family_usd_key("juka_live", 1_000_000 // 3600)] = 600_000
        assert sg.session_headroom("juka_live") == sg.HEADROOM_FAMILY_OVER
        redis.d[sg._usd_key(1_000_000 // 3600)] = 1_000_000
        assert sg.session_headroom("juka_live") == sg.HEADROOM_GLOBAL_OVER
    finally:
        sg.set_redis_factory(None)
        sg.set_clock(None)
        llmroute.set_client_for_test(None)


def test_estimate_prices_the_failover_model_without_the_store():
    llmroute.set_client_for_test(None)
    assert llmroute.model_price("gpt-6-luna") == (0.10, 0.50)
    usd = llmroute.estimate_usd("gpt-6-luna", 1_000_000, 1_000_000)
    assert usd == pytest.approx(0.60)


def _claude_store():
    routes = {
        "items": [
            {"family": "scene_pack", "model": "claude-haiku-5-5", "thinking_budget": -1},
            {"family": "juka_hints", "model": "claude-haiku-5-5", "thinking_budget": -1},
        ]
    }
    models = {
        "items": [
            {"model": "claude-haiku-5-5", "provider": "anthropic", "input_usd_per_mtok": 0.1, "output_usd_per_mtok": 0.5},
        ]
    }
    return _fake_store(routes, models)


def test_a_process_that_declares_no_provider_refuses_a_claude_route(monkeypatch):
    monkeypatch.setattr(llmroute, "_DRIVABLE", dict(llmroute._DRIVABLE))
    monkeypatch.setattr(httpx, "get", _claude_store())
    client = llmroute.RouteClient("http://loc")
    assert client.resolve("scene_pack", "gemini-default").model == "gemini-default"


def test_a_process_that_drives_claude_for_every_family_serves_the_route(monkeypatch):
    monkeypatch.setattr(llmroute, "_DRIVABLE", dict(llmroute._DRIVABLE))
    llmroute.allow_providers({"anthropic", "openai"})
    monkeypatch.setattr(httpx, "get", _claude_store())
    client = llmroute.RouteClient("http://loc")
    got = client.resolve("scene_pack", "gemini-default")
    assert (got.model, got.provider) == ("claude-haiku-5-5", "anthropic")
    assert llmroute.can_drive("exercise_judge", "openai")


def test_a_provider_allowed_for_some_families_stays_refused_for_the_rest(monkeypatch):
    monkeypatch.setattr(llmroute, "_DRIVABLE", dict(llmroute._DRIVABLE))
    llmroute.allow_providers({"anthropic"}, families={"scene_pack"})
    monkeypatch.setattr(httpx, "get", _claude_store())
    client = llmroute.RouteClient("http://loc")
    assert client.resolve("scene_pack", "gemini-default").model == "claude-haiku-5-5"
    assert client.resolve("juka_hints", "gemini-default").model == "gemini-default"
    assert llmroute.can_drive("juka_live", "openai") and not llmroute.can_drive("scene_pack", "openai")


def test_claude_models_are_inferred_as_anthropic():
    assert llmroute.infer_provider("claude-haiku-5-5") == "anthropic"


# ---- canary candidate, keyed selection ----------------------------------


def _canary_store(
    share=50, candidate="claude-haiku-5-5", thinking=-1, route_model="gemini-3.8-flash"
):
    routes = {
        "items": [
            {
                "family": "scene_pack",
                "model": route_model,
                "thinking_budget": 768,
                "daily_budget_usd": 2.5,
                "candidate_model": candidate,
                "candidate_thinking_budget": thinking,
                "candidate_share": share,
            }
        ]
    }
    models = {
        "items": [
            {
                "model": "gemini-3.8-flash",
                "provider": "google",
                "input_usd_per_mtok": 0.75,
                "output_usd_per_mtok": 3.75,
            },
            {
                "model": "claude-haiku-5-5",
                "provider": "anthropic",
                "input_usd_per_mtok": 0.1,
                "output_usd_per_mtok": 0.5,
            },
        ]
    }
    return routes, models


@pytest.fixture
def drives_claude(monkeypatch):
    monkeypatch.setattr(llmroute, "_DRIVABLE", dict(llmroute._DRIVABLE))
    monkeypatch.setattr(llmroute, "_queue_capability_report", lambda: None)
    llmroute.allow_providers({"anthropic"})


def _canary_client(monkeypatch, **kw):
    routes, models = _canary_store(**kw)
    monkeypatch.setattr(httpx, "get", _fake_store(routes, models))
    return llmroute.RouteClient("http://loc")


def test_a_route_without_a_candidate_is_the_route_variant(monkeypatch):
    routes = {"items": [{"family": "scene_pack", "model": "gemini-3.8-flash"}]}
    monkeypatch.setattr(httpx, "get", _fake_store(routes, _models("gemini-3.8-flash")))
    got = llmroute.RouteClient("http://loc").resolve("scene_pack", "d", key="deck-1")
    assert (got.model, got.variant, got.requested) == ("gemini-3.8-flash", "route", "")
    assert llmroute.resolve("x", "d").variant == "route"


def test_a_candidate_share_picks_by_a_stable_hash_of_the_key(
    monkeypatch, drives_claude
):
    client = _canary_client(monkeypatch, share=50, thinking=0)
    # crc32("scene_pack:<key>") % 100: deck-1=15 and deck-3=27 are below 50, deck-2=65 and deck-4=60 are not.
    for key, variant in [
        ("deck-1", "candidate"),
        ("deck-2", "route"),
        ("deck-3", "candidate"),
        ("deck-4", "route"),
    ]:
        for _ in range(3):
            assert client.resolve("scene_pack", "d", key=key).variant == variant, key
    cand = client.resolve("scene_pack", "d", key="deck-1")
    assert (cand.model, cand.provider, cand.thinking_budget, cand.daily_budget_usd) == (
        "claude-haiku-5-5",
        "anthropic",
        0,
        2.5,
    )
    inc = client.resolve("scene_pack", "d", key="deck-2")
    assert (inc.model, inc.provider, inc.thinking_budget) == (
        "gemini-3.8-flash",
        "google",
        768,
    )


def test_the_hash_is_crc32_of_family_colon_key(monkeypatch):
    for family, key, bucket in [
        ("scene_pack", "deck-1", 15),
        ("scene_pack", "ünï-ключ", 6),
        ("exercise_judge", "ex-42", 9),
    ]:
        assert llmroute._in_share(family, key, bucket + 1) is True
        assert llmroute._in_share(family, key, bucket) is False
    assert llmroute._in_share("f", 42, 100) is True
    assert llmroute._in_share("f", "k", 0) is False


def test_the_share_is_honoured_across_many_keys(monkeypatch, drives_claude):
    client = _canary_client(monkeypatch, share=20)
    hits = sum(
        client.resolve("scene_pack", "d", key=f"item-{i}").variant == "candidate"
        for i in range(2000)
    )
    assert 300 <= hits <= 500


def test_share_100_sends_every_key_and_0_sends_none(monkeypatch, drives_claude):
    full = _canary_client(monkeypatch, share=100)
    assert all(
        full.resolve("scene_pack", "d", key=f"k{i}").variant == "candidate"
        for i in range(50)
    )
    none = _canary_client(monkeypatch, share=0)
    assert all(
        none.resolve("scene_pack", "d", key=f"k{i}").variant == "route"
        for i in range(50)
    )


def test_no_key_draws_per_call(monkeypatch, drives_claude):
    client = _canary_client(monkeypatch, share=30)
    draws = iter([10, 29, 30, 99])
    monkeypatch.setattr(llmroute.random, "randrange", lambda n: next(draws))
    got = [client.resolve("scene_pack", "d").variant for _ in range(4)]
    assert got == ["candidate", "candidate", "route", "route"]
    draws = iter([5])
    monkeypatch.setattr(llmroute.random, "randrange", lambda n: next(draws))
    assert client.resolve("scene_pack", "d", key="").variant == "candidate"


def test_a_candidate_this_process_cannot_drive_never_runs(monkeypatch, caplog):
    monkeypatch.setattr(llmroute, "_DRIVABLE", dict(llmroute._DRIVABLE))
    client = _canary_client(monkeypatch, share=100)
    with caplog.at_level("ERROR"):
        for i in range(3):
            got = client.resolve("scene_pack", "d", key=f"k{i}")
            assert (got.model, got.variant) == ("gemini-3.8-flash", "route")
    assert caplog.text.count("cannot drive provider=anthropic") == 1


def test_a_candidate_missing_from_the_registry_never_runs(monkeypatch, drives_claude):
    routes, _ = _canary_store(share=100, candidate="gone-model")
    monkeypatch.setattr(httpx, "get", _fake_store(routes, _models("gemini-3.8-flash")))
    got = llmroute.RouteClient("http://loc").resolve("scene_pack", "d", key="k")
    assert (got.model, got.variant) == ("gemini-3.8-flash", "route")


def test_a_candidate_equal_to_the_route_model_is_not_a_canary(
    monkeypatch, drives_claude
):
    client = _canary_client(monkeypatch, share=100, candidate="gemini-3.8-flash")
    assert client.resolve("scene_pack", "d", key="k").variant == "route"


def test_stored_route_stays_the_incumbent_while_a_canary_runs(
    monkeypatch, drives_claude
):
    client = _canary_client(monkeypatch, share=100)
    assert client.route("scene_pack").model == "gemini-3.8-flash"
    assert client.route("scene_pack").variant == "route"


def test_a_malformed_candidate_does_not_break_the_route_table(
    monkeypatch, drives_claude
):
    routes = {
        "items": [
            {
                "family": "a",
                "model": "gemini-3.8-flash",
                "candidate_model": "claude-haiku-5-5",
                "candidate_share": "lots",
            },
            {
                "family": "b",
                "model": "gemini-3.8-flash",
                "candidate_model": "claude-haiku-5-5",
                "candidate_share": 250,
            },
            {
                "family": "c",
                "model": "gemini-3.8-flash",
                "candidate_model": None,
                "candidate_share": 50,
            },
        ]
    }
    _, models = _canary_store()
    monkeypatch.setattr(httpx, "get", _fake_store(routes, models))
    client = llmroute.RouteClient("http://loc")
    assert client.resolve("a", "d", key="k").variant == "route"
    assert client.resolve("b", "d", key="k").variant == "candidate"
    assert client.resolve("c", "d", key="k").variant == "route"


def test_a_candidate_is_served_beside_a_refused_route_and_is_not_a_fallback(
    monkeypatch, drives_claude
):
    routes, models = _canary_store(share=40, route_model="retired-model")
    models["items"].append(
        {"model": "retired-model", "provider": "google", "active": False}
    )
    monkeypatch.setattr(httpx, "get", _fake_store(routes, models))
    client = llmroute.RouteClient("http://loc")
    llmroute.set_client_for_test(client, _recorder(monkeypatch))
    try:
        monkeypatch.setattr(llmroute.random, "randrange", lambda n: 10)
        cand = client.resolve("scene_pack", "dflt")
        assert (cand.model, cand.variant, cand.requested) == (
            "claude-haiku-5-5",
            "candidate",
            "",
        )
        monkeypatch.setattr(llmroute.random, "randrange", lambda n: 90)
        miss = client.resolve("scene_pack", "dflt")
        assert (miss.model, miss.requested, miss.variant) == (
            "dflt",
            "retired-model",
            "route",
        )
        llmroute.record_call("scene_pack", "claude-haiku-5-5")
        llmroute.record_call("scene_pack", "dflt")
        rows = {r["model"]: r for r in llmroute._recorder.drain()}
        assert rows["claude-haiku-5-5"]["fallbacks"] == 0
        assert rows["dflt"]["fallbacks"] == 1
    finally:
        llmroute.set_client_for_test(None)


def test_the_snapshot_carries_the_candidate_into_a_cold_start(
    monkeypatch, drives_claude
):
    routes, models = _canary_store(share=100)
    store = _Snapshots()
    monkeypatch.setattr(httpx, "get", _fake_store(routes, models))
    first = llmroute.RouteClient("http://loc")
    first.set_snapshot_store(store.load, store.save)
    first.warm()

    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "get", boom)
    cold = llmroute.RouteClient("http://loc")
    cold.set_snapshot_store(store.load, store.save)
    cold.warm()
    assert cold.resolve("scene_pack", "d", key="k").variant == "candidate"


def test_the_module_resolve_passes_the_key_through(monkeypatch, drives_claude):
    llmroute.set_client_for_test(_canary_client(monkeypatch, share=50))
    try:
        assert llmroute.resolve("scene_pack", "d", key="deck-1").variant == "candidate"
        assert llmroute.resolve("scene_pack", "d", -1, "", "deck-2").variant == "route"
    finally:
        llmroute.set_client_for_test(None)
    assert llmroute.resolve("scene_pack", "d", key="deck-1").variant == "route"


# ---- outcomes, fallbacks, accepted / rejected ---------------------------


def _recorder(monkeypatch):
    rec = llmroute.UsageRecorder(
        "svc", "http://loc", "k", flush_seconds=3600, clock=lambda: 7200.0 + 5
    )
    monkeypatch.setattr(rec, "_ensure_thread", lambda: None)
    return rec


def test_outcomes_count_errors_and_fallbacks_under_the_model_that_ran(monkeypatch):
    rec = _recorder(monkeypatch)
    rec.record("f", "m", latency_ms=10)
    rec.record("f", "m", latency_ms=10, outcome="error")
    rec.record("f", "m", latency_ms=10, outcome="refused")
    rec.record("f", "m", latency_ms=10, outcome="invalid_output")
    rec.record("f", "m", latency_ms=10, error=True)
    rec.record("f", "m", latency_ms=10, fallback=True)
    rec.record("f", "default-model", latency_ms=10, fallback=True)
    rows = {r["model"]: r for r in rec.drain()}
    assert (rows["m"]["calls"], rows["m"]["errors"], rows["m"]["fallbacks"]) == (
        6,
        3,
        1,
    )
    assert (rows["default-model"]["calls"], rows["default-model"]["fallbacks"]) == (
        1,
        1,
    )
    assert (rows["m"]["accepted"], rows["m"]["rejected"]) == (0, 0)


def test_record_outcome_adds_accepted_and_rejected_to_the_hourly_row(monkeypatch):
    posted = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        posted["json"] = json
        return _Resp({})

    monkeypatch.setattr(httpx, "post", fake_post)
    rec = _recorder(monkeypatch)
    rec.record("f", "m", usd=0.1, latency_ms=20)
    rec.record_outcome("f", "m", True)
    rec.record_outcome("f", "m", True, n=3)
    rec.record_outcome("f", "m", False, n=2)
    rec.record_outcome("f", "m", True, n=0)
    rec.record_outcome("f", "m", True, n=-4)
    rec.record_outcome("", "m", True)
    assert rec.flush() is True
    (row,) = posted["json"]["rows"]
    assert (row["calls"], row["accepted"], row["rejected"], row["fallbacks"]) == (
        1,
        4,
        2,
        0,
    )
    assert row["latency_ms_p50"] == 20


def test_an_outcome_only_row_sends_no_latency(monkeypatch):
    rec = _recorder(monkeypatch)
    rec.record_outcome("f", "m", False)
    (row,) = rec.drain()
    assert (row["calls"], row["rejected"]) == (0, 1)
    assert row["latency_ms_p50"] is None and row["latency_ms_p95"] is None
    assert llmroute.UsageRecorder("svc", "").enabled is False
    llmroute.UsageRecorder("svc", "").record_outcome("f", "m", True)


def test_a_failed_flush_keeps_outcomes_and_fallbacks(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "post", boom)
    rec = _recorder(monkeypatch)
    rec.record("f", "m", fallback=True)
    rec.record_outcome("f", "m", True, n=2)
    rec.record_outcome("f", "m", False)
    assert rec.flush() is False
    (row,) = rec.drain()
    assert (row["calls"], row["accepted"], row["rejected"], row["fallbacks"]) == (
        1,
        2,
        1,
        1,
    )


def test_record_call_and_record_outcome_reach_the_recorder(monkeypatch):
    rec = _recorder(monkeypatch)
    monkeypatch.setattr(llmroute, "_recorder", rec)
    monkeypatch.setattr(llmroute, "_client", None)
    llmroute.record_call("f", "m", usd=0.01, outcome="refused", fallback=True)
    llmroute.record_call("f", "m", error=True)
    llmroute.record_outcome("f", "m", True, n=5)
    (row,) = rec.drain()
    assert (row["calls"], row["errors"], row["fallbacks"], row["accepted"]) == (
        2,
        2,
        1,
        5,
    )


def test_record_call_never_raises(monkeypatch):
    rec = _recorder(monkeypatch)
    monkeypatch.setattr(llmroute, "_recorder", rec)
    llmroute.record_call("f", "m", usd="not a number", surprise_kwarg=1)
    llmroute.record_call("f", "m", outcome=None, latency_ms=None)
    llmroute.record_outcome("f", "m", True, n="x")


def test_a_refused_route_marks_the_default_call_as_a_fallback(monkeypatch):
    monkeypatch.setattr(llmroute, "_DRIVABLE", dict(llmroute._DRIVABLE))
    monkeypatch.setattr(httpx, "get", _claude_store())
    client = llmroute.RouteClient("http://loc")
    llmroute.set_client_for_test(client, _recorder(monkeypatch))
    try:
        got = client.resolve("scene_pack", "gemini-default")
        assert (got.model, got.requested, got.variant) == (
            "gemini-default",
            "claude-haiku-5-5",
            "route",
        )
        llmroute.record_call("scene_pack", "gemini-default", usd=0.01)
        llmroute.record_call("scene_pack", "claude-haiku-5-5")
        llmroute.record_call("other_family", "gemini-default")
        rows = {(r["family"], r["model"]): r for r in llmroute._recorder.drain()}
        assert rows[("scene_pack", "gemini-default")]["fallbacks"] == 1
        assert rows[("scene_pack", "claude-haiku-5-5")]["fallbacks"] == 0
        assert rows[("other_family", "gemini-default")]["fallbacks"] == 0
        llmroute.record_call("scene_pack", "gemini-default", fallback=False)
        assert llmroute._recorder.drain()[0]["fallbacks"] == 0
    finally:
        llmroute.set_client_for_test(None)


def test_a_served_route_is_not_a_fallback(monkeypatch, drives_claude):
    client = _canary_client(monkeypatch, share=0)
    llmroute.set_client_for_test(client, _recorder(monkeypatch))
    try:
        client.resolve("scene_pack", "d")
        llmroute.record_call("scene_pack", "gemini-3.8-flash")
        assert llmroute._recorder.drain()[0]["fallbacks"] == 0
    finally:
        llmroute.set_client_for_test(None)


# ---- the LLM_CALL line --------------------------------------------------


def test_every_call_logs_one_llm_call_line(monkeypatch, caplog, drives_claude):
    client = _canary_client(monkeypatch, share=100)
    monkeypatch.setattr(llmroute, "_service", "kielolearn-engine")
    llmroute.set_client_for_test(client, None)
    try:
        client.resolve("scene_pack", "d", key="deck-1")
        with caplog.at_level("INFO", logger="kielo_shared.llmroute"):
            llmroute.record_call(
                "scene_pack",
                "claude-haiku-5-5",
                input_tokens=120,
                output_tokens=45,
                thinking_tokens=7,
                usd=0.00123456,
                latency_ms=842.9,
            )
        lines = [
            r.getMessage()
            for r in caplog.records
            if r.getMessage().startswith("LLM_CALL ")
        ]
        assert lines == [
            "LLM_CALL service=kielolearn-engine family=scene_pack model=claude-haiku-5-5 provider=anthropic "
            "variant=candidate in=120 out=45 thinking=7 usd=0.001235 latency_ms=842 outcome=ok fallback=0"
        ]
    finally:
        llmroute.set_client_for_test(None)


def test_the_llm_call_line_names_errors_fallbacks_and_unknowns(monkeypatch, caplog):
    monkeypatch.setattr(llmroute, "_service", "")
    llmroute.set_client_for_test(None)
    with caplog.at_level("INFO", logger="kielo_shared.llmroute"):
        llmroute.record_call("", "weird model", error=True, fallback=True)
        llmroute.record_call(
            "f", "gpt-6-luna", outcome="invalid_output", variant="candidate"
        )
    lines = [
        r.getMessage() for r in caplog.records if r.getMessage().startswith("LLM_CALL ")
    ]
    assert lines[0] == (
        "LLM_CALL service=- family=- model=weird_model provider=- variant=route in=0 out=0 thinking=0 "
        "usd=0.000000 latency_ms=0 outcome=error fallback=1"
    )
    assert (
        "provider=openai variant=candidate" in lines[1]
        and "outcome=invalid_output fallback=0" in lines[1]
    )


# ---- capability report --------------------------------------------------


def _wait_for_reporter():
    deadline = time.time() + 3
    while llmroute._capability_running and time.time() < deadline:
        time.sleep(0.01)
    assert not llmroute._capability_running


@pytest.fixture
def capability_env(monkeypatch):
    posts = []

    def fake_post(url, json=None, headers=None, timeout=None):
        posts.append((url, json, headers))
        return _Resp({})

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(llmroute, "_DRIVABLE", dict(llmroute._DRIVABLE))
    monkeypatch.setattr(llmroute, "_CAPABILITY_DELAY_SECONDS", 0.05)
    monkeypatch.setattr(llmroute, "_service", "")
    monkeypatch.setattr(llmroute, "_client", None)
    monkeypatch.setattr(llmroute, "_recorder", None)
    monkeypatch.setattr(llmroute, "_capability_pending", False)
    return posts


def test_the_payload_always_lists_google_and_what_was_declared(
    capability_env, monkeypatch
):
    monkeypatch.setattr(llmroute, "_service", "svc")
    payload = llmroute.capabilities_payload()
    assert payload["service"] == "svc"
    assert payload["providers"][0] == {"provider": "google", "families": None}
    openai = next(p for p in payload["providers"] if p["provider"] == "openai")
    assert openai["families"] == sorted(llmroute.OPENAI_CAPABLE_FAMILIES)
    assert all(p["provider"] != "anthropic" for p in payload["providers"])
    llmroute.allow_providers({"anthropic"}, families={"scene_pack", "exercise_judge"})
    anth = next(
        p
        for p in llmroute.capabilities_payload()["providers"]
        if p["provider"] == "anthropic"
    )
    assert anth["families"] == ["exercise_judge", "scene_pack"]
    llmroute.allow_providers({"anthropic", "openai"})
    by = {
        p["provider"]: p["families"]
        for p in llmroute.capabilities_payload()["providers"]
    }
    assert by == {"google": None, "openai": None, "anthropic": None}


def test_configure_from_env_posts_the_capabilities_once_from_a_thread(
    capability_env, monkeypatch
):
    monkeypatch.setenv("LOCALIZATION_SERVICE_URL", "http://loc/")
    monkeypatch.setenv("KIELO_INTERNAL_API_KEY", "secret")
    llmroute.configure_from_env("kielolearn-engine")
    assert capability_env == []  # a background post, not a blocking one
    llmroute.allow_providers({"anthropic", "openai"})  # declared right after start-up
    _wait_for_reporter()
    assert len(capability_env) == 1
    url, body, headers = capability_env[0]
    assert url == "http://loc/internal/api/v3/localization/llm-capabilities"
    assert headers == {"X-Internal-API-Key": "secret"}
    assert body["service"] == "kielolearn-engine"
    assert {p["provider"]: p["families"] for p in body["providers"]} == {
        "google": None,
        "openai": None,
        "anthropic": None,
    }


def test_declaring_providers_later_sends_a_fresh_report(capability_env, monkeypatch):
    llmroute.configure("svc", "http://loc", "k")
    llmroute.allow_providers({"anthropic"}, families={"scene_pack"})
    _wait_for_reporter()
    llmroute.allow_providers({"anthropic"})
    _wait_for_reporter()
    assert [
        {p["provider"]: p["families"] for p in body["providers"]}.get("anthropic")
        for _, body, _ in capability_env
    ] == [["scene_pack"], None]


def test_no_report_without_a_store_or_a_service(capability_env, monkeypatch):
    monkeypatch.delenv("LOCALIZATION_SERVICE_URL", raising=False)
    llmroute.configure_from_env("svc")
    llmroute.allow_providers({"anthropic"})
    llmroute.configure("", "http://loc")
    llmroute.allow_providers({"anthropic"})
    time.sleep(0.2)
    assert capability_env == [] and not llmroute._capability_running


def test_a_failing_capability_post_is_swallowed(capability_env, monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "post", boom)
    llmroute.configure("svc", "http://loc", "k")
    llmroute.allow_providers({"anthropic"})
    _wait_for_reporter()
    assert llmroute.RouteClient("http://loc").report_capabilities({}) is False
    assert llmroute.RouteClient("").report_capabilities({}) is False


def test_a_reporter_thread_that_cannot_start_never_breaks_start_up(
    capability_env, monkeypatch
):
    llmroute.configure("svc", "http://loc", "k")

    def no_threads(*a, **k):
        raise RuntimeError("can't start new thread")

    with monkeypatch.context() as patched:
        patched.setattr(llmroute.threading, "Thread", no_threads)
        llmroute.allow_providers({"anthropic"})
    assert llmroute._capability_running is False
    llmroute.allow_providers({"anthropic"})
    _wait_for_reporter()
    assert len(capability_env) == 1


def test_resolve_goes_through_an_overridden_route(monkeypatch):
    class Stored(llmroute.RouteClient):
        def route(self, family):
            return llmroute.Route("stored-model", provider="openai")

    client = Stored("http://stored.invalid")
    monkeypatch.setattr(httpx, "get", lambda *a, **k: pytest.fail("no fetch expected"))
    got = client.resolve("juka_hints", "gemini-default")
    assert (got.model, got.provider, got.variant, got.requested) == (
        "stored-model",
        "openai",
        "route",
        "",
    )


def test_a_refresh_that_cannot_decode_the_routes_keeps_the_old_candidates(monkeypatch):
    good = {
        "items": [
            {
                "family": "scene_pack",
                "model": "m-a",
                "thinking_budget": -1,
                "candidate_model": "m-b",
                "candidate_thinking_budget": -1,
                "candidate_share": 100,
            }
        ]
    }
    bad = {"items": [{"family": "scene_pack", "model": "m-a", "thinking_budget": "x"}]}
    models = _models("m-a", "m-b")
    state = {"routes": good}

    def fake_get(url, headers=None, timeout=None):
        return _Resp(models if url.endswith("/llm-models") else state["routes"])

    monkeypatch.setattr(httpx, "get", fake_get)
    now = [100.0]
    client = llmroute.RouteClient("http://loc", ttl=10, clock=lambda: now[0])
    assert client.resolve("scene_pack", "d", key="k").model == "m-b"
    state["routes"] = bad
    now[0] += 60
    client._refresh()
    assert client.resolve("scene_pack", "d", key="k").model == "m-b"
