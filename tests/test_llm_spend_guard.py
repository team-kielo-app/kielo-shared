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
        "ENV",
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


def test_env_spelling_also_marks_production():
    # The convo VM sets ENV=production, not ENVIRONMENT (2026-10-03).
    from kielo_shared.llm.spend_guard import is_production

    assert is_production({"ENV": "production"})
    assert not is_production({"ENV": "development"})
    assert not is_production({"ENVIRONMENT": "development", "ENV": "production"})



def test_legacy_env_spelling_counts_as_the_environment(monkeypatch):
    # The convo VM set only ENV=production; it must count as production, and
    # an explicit non-prod ENV (a test runner) must not be overridden by
    # K_SERVICE.
    monkeypatch.setenv("ENV", "production")
    sg.admit_paid_call("t")
    monkeypatch.setenv("ENV", "test")
    monkeypatch.setenv("K_SERVICE", "svc")
    with pytest.raises(sg.PaidLLMCallsDisabled):
        sg.admit_paid_call("t")


# ----------------------------------------------- redis wiring and the audio loop


@pytest.mark.parametrize(
    "env,want",
    [
        ({"REDIS_HOST": "h:6379"}, ("h", 6379, "")),
        ({"REDIS_HOST": "10.0.0.3:6380"}, ("10.0.0.3", 6380, "")),
        ({"REDIS_HOST": "h", "REDIS_PORT": "6381"}, ("h", 6381, "")),
        ({"REDIS_HOST": "h"}, ("h", 6379, "")),
        ({"REDIS_HOST": "h:6379", "REDIS_PORT": "9999"}, ("h", 6379, "")),
        ({"REDIS_HOST": "h:notaport"}, ("h:notaport", 6379, "")),
        (
            {"REDIS_URL": "redis://u:pw@cache.internal:6390/2"},
            ("", 6379, "redis://u:pw@cache.internal:6390/2"),
        ),
        (
            {"REDIS_HOST": "redis://cache.internal:6391/0"},
            ("", 6379, "redis://cache.internal:6391/0"),
        ),
        (
            {"REDIS_URL": "redis://a:1/0", "REDIS_HOST": "h:6379"},
            ("", 6379, "redis://a:1/0"),
        ),
    ],
)
def test_redis_target_parses_host_port_and_urls(env, want):
    target = sg.redis_target(env)
    assert (target.host, target.port, target.url) == want


def test_redis_target_carries_the_password_and_needs_a_host():
    assert sg.redis_target({"REDIS_HOST": "h:1", "REDIS_PASSWORD": "pw"}).password == "pw"
    with pytest.raises(RuntimeError):
        sg.redis_target({})


def test_the_guard_waits_on_redis_for_a_short_bounded_time():
    assert sg._REDIS_TIMEOUT_SECONDS <= 0.25
    assert sg._LOOP_WAIT_SECONDS <= 0.3


class _UnresponsiveStore:
    """A store that is up but never answers within the guard's patience."""

    def __init__(self, seconds: float = 1.0) -> None:
        self.seconds = seconds

    def mget(self, keys):
        import time

        time.sleep(self.seconds)
        return [None] * len(keys)

    def incrby(self, key, n):
        import time

        time.sleep(self.seconds)
        return n

    def expire(self, *_a):
        return True


def _prod_with_budget(monkeypatch):
    for k in ("REDIS_URL", "REDIS_HOST", "ENV", "K_SERVICE", "LLM_HOURLY_CALL_CAP"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("LLM_DAILY_BUDGET_USD", "5")


def test_an_unresponsive_store_fails_open_within_the_loop_wait(monkeypatch):
    import asyncio
    import time

    _prod_with_budget(monkeypatch)
    sg.set_redis_factory(lambda: _UnresponsiveStore())

    async def main():
        started = time.monotonic()
        result = sg.session_headroom("juka_live")
        sg.record_usd(0.01, family="juka_live")
        return result, time.monotonic() - started

    try:
        result, elapsed = asyncio.run(main())
    finally:
        sg.set_redis_factory(None)
    assert result == sg.HEADROOM_OK
    assert elapsed < 0.6


def test_the_audio_loop_never_stalls_on_the_guard(monkeypatch):
    import asyncio
    import time

    _prod_with_budget(monkeypatch)
    sg.set_redis_factory(lambda: _UnresponsiveStore())

    async def main():
        worst = 0.0
        stop = False

        async def probe():
            nonlocal worst
            last = time.monotonic()
            while not stop:
                await asyncio.sleep(0.005)
                now = time.monotonic()
                worst = max(worst, now - last - 0.005)
                last = now

        task = asyncio.create_task(probe())
        await asyncio.sleep(0.05)
        result = await sg.asession_headroom("juka_live")
        for _ in range(5):
            sg.record_usd(0.01, family="juka_live")
        await asyncio.sleep(0.05)
        stop = True
        await task
        return result, worst

    try:
        result, worst = asyncio.run(main())
    finally:
        sg.set_redis_factory(None)
    assert result == sg.HEADROOM_OK
    assert worst < 0.1, f"event loop stalled for {worst:.3f}s"


def test_record_usd_never_raises_after_the_executor_shuts_down(monkeypatch, caplog):
    import asyncio
    import logging

    class _Dead:
        def submit(self, *a, **k):
            raise RuntimeError("cannot schedule new futures after interpreter shutdown")

    monkeypatch.setattr(sg, "_executor", _Dead())

    async def main():
        sg.record_usd(0.01, family="juka_live")

    with caplog.at_level(logging.WARNING):
        asyncio.run(main())
    assert "dropped" in caplog.text
