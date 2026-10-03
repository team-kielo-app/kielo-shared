import asyncio

import pytest

from kielo_shared.llm import LLMRequest, OpenAILLMProvider
from kielo_shared.llm import spend_guard as sg


class FakeRedis:
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


class DownRedis:
    def incr(self, k):
        raise ConnectionError("down")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in (
        "ENVIRONMENT",
        "K_SERVICE",
        "LLM_ALLOW_PAID_CALLS",
        "LLM_DAILY_BUDGET_USD",
        "LLM_HOURLY_CALL_CAP",
        "LLM_GUARD_EST_USD_PER_CALL",
    ):
        monkeypatch.delenv(k, raising=False)
    sg.set_clock(lambda: 1_000_000.0)
    yield
    sg.set_redis_factory(None)
    sg.set_clock(None)


def test_nonprod_refuses_without_allow(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    sg.set_redis_factory(FakeRedis)
    with pytest.raises(sg.PaidLLMCallsDisabled):
        sg.admit_paid_call("t")


def test_unset_environment_is_nonprod_unless_cloud_run(monkeypatch):
    with pytest.raises(sg.PaidLLMCallsDisabled):
        sg.admit_paid_call("t")
    monkeypatch.setenv("K_SERVICE", "svc")
    sg.admit_paid_call("t")


def test_production_unlimited_by_default(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    sg.set_redis_factory(DownRedis)
    for _ in range(500):
        sg.admit_paid_call("t")


def test_hourly_cap(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("LLM_ALLOW_PAID_CALLS", "true")
    monkeypatch.setenv("LLM_HOURLY_CALL_CAP", "3")
    sg.set_redis_factory(FakeRedis)
    for _ in range(3):
        sg.admit_paid_call("t")
    with pytest.raises(sg.LLMBudgetExceeded) as ei:
        sg.admit_paid_call("t")
    assert ei.value.reason == "hourly_cap"


def test_daily_budget_rolls_and_settles(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("LLM_ALLOW_PAID_CALLS", "true")
    monkeypatch.setenv("LLM_DAILY_BUDGET_USD", "0.01")
    monkeypatch.setenv("LLM_GUARD_EST_USD_PER_CALL", "0.004")
    now = [1_000_000.0]
    sg.set_clock(lambda: now[0])
    sg.set_redis_factory(FakeRedis)
    sg.admit_paid_call("t")
    sg.admit_paid_call("t")
    sg.record_actual_usd(0.02)
    with pytest.raises(sg.LLMBudgetExceeded) as ei:
        sg.admit_paid_call("t")
    assert ei.value.reason == "daily_budget"
    now[0] += 25 * 3600
    sg.admit_paid_call("t")


def test_nonprod_fails_closed_when_redis_down(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("LLM_ALLOW_PAID_CALLS", "true")
    sg.set_redis_factory(DownRedis)
    with pytest.raises(sg.LLMGuardUnavailable):
        sg.admit_paid_call("t")


def test_prod_with_budget_fails_open_when_redis_down(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("LLM_DAILY_BUDGET_USD", "5")
    sg.set_redis_factory(DownRedis)
    sg.admit_paid_call("t")


def test_provider_refuses_before_generator_runs(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    calls = []

    async def text(system, user, variables):
        calls.append(1)
        return "x"

    provider = OpenAILLMProvider(text)
    req = LLMRequest(system_prompt="s", user_prompt="u", task="t")
    with pytest.raises(sg.PaidLLMCallsDisabled):
        asyncio.run(provider.generate(req))
    assert calls == []
