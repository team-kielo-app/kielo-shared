"""The guard's Redis traffic is batched (one script per admission, one pipeline
per booking). Decisions and resulting counters must equal the sequential path.

Needs fakeredis + lupa (Lua); skipped without them.
"""

from __future__ import annotations

import pytest

fakeredis = pytest.importorskip("fakeredis")
pytest.importorskip("lupa")

from kielo_shared.llm import spend_guard as sg

NOW = 1_000_000.0
ENV_KEYS = (
    "ENVIRONMENT",
    "ENV",
    "K_SERVICE",
    "LLM_ALLOW_PAID_CALLS",
    "LLM_DAILY_BUDGET_USD",
    "LLM_HOURLY_CALL_CAP",
    "LLM_GUARD_EST_USD_PER_CALL",
)


class CountingRedis(fakeredis.FakeRedis):
    """round_trips = commands sent on their own + one per pipeline execute."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.round_trips = 0

    def execute_command(self, *a, **kw):
        self.round_trips += 1
        return super().execute_command(*a, **kw)

    def pipeline(self, *a, **kw):
        pipe = super().pipeline(*a, **kw)
        real_execute = pipe.execute
        client = self

        def counted(*x, **y):
            client.round_trips += 1
            return real_execute(*x, **y)

        pipe.execute = counted
        pipe.execute_command = lambda *x, **y: type(pipe).execute_command(pipe, *x, **y)
        return pipe


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    sg.set_clock(lambda: NOW)
    yield
    sg.set_redis_factory(None)
    sg.set_clock(None)


def _dump(r) -> dict:
    return {k: (r.get(k), r.ttl(k)) for k in sorted(r.keys("*"))}


def _setup(monkeypatch, env: dict, family_budget: float, seed: dict | None):
    for k in ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(sg, "_family_budget", lambda f: family_budget if f else 0.0)
    r = CountingRedis(server=fakeredis.FakeServer(), decode_responses=True)
    for k, v in (seed or {}).items():
        r.set(k, v)
    sg.set_redis_factory(lambda: r)
    return r


def _run(calls: int, family: str) -> list[str]:
    out = []
    for _ in range(calls):
        try:
            sg.admit_paid_call("t", family=family)
            out.append("ok")
        except sg.PaidLLMCallRefused as exc:
            out.append(f"{type(exc).__name__}:{exc.reason}:{exc}")
    return out


B = sg._bucket(NOW)
PROD = {"ENVIRONMENT": "production"}
DEV = {"ENVIRONMENT": "development", "LLM_ALLOW_PAID_CALLS": "true"}

SCENARIOS = {
    "under_caps": (
        DEV | {"LLM_DAILY_BUDGET_USD": "1", "LLM_HOURLY_CALL_CAP": "50"},
        "",
        0,
        None,
        3,
    ),
    "hourly_cap_at_and_over": (
        DEV | {"LLM_DAILY_BUDGET_USD": "0", "LLM_HOURLY_CALL_CAP": "2"},
        "",
        0,
        None,
        4,
    ),
    "daily_budget_at_cap": (
        DEV | {"LLM_DAILY_BUDGET_USD": "0.01", "LLM_HOURLY_CALL_CAP": "0"},
        "",
        0,
        {sg._usd_key(B): "9000"},
        3,
    ),
    "daily_budget_spread_over_window": (
        DEV | {"LLM_DAILY_BUDGET_USD": "0.01", "LLM_HOURLY_CALL_CAP": "0"},
        "",
        0,
        {sg._usd_key(B - 23): "5000", sg._usd_key(B - 5): "5001"},
        2,
    ),
    "daily_budget_expired_bucket_ignored": (
        DEV | {"LLM_DAILY_BUDGET_USD": "0.01", "LLM_HOURLY_CALL_CAP": "0"},
        "",
        0,
        {sg._usd_key(B - 24): "99999999"},
        2,
    ),
    "family_cap_under": (
        DEV | {"LLM_DAILY_BUDGET_USD": "1", "LLM_HOURLY_CALL_CAP": "50"},
        "chat",
        1.0,
        None,
        3,
    ),
    "family_cap_at_cap": (
        DEV | {"LLM_DAILY_BUDGET_USD": "1", "LLM_HOURLY_CALL_CAP": "50"},
        "chat",
        0.005,
        {sg._family_usd_key("chat", B): "5000"},
        2,
    ),
    "family_cap_crossed_mid_run": (
        DEV | {"LLM_DAILY_BUDGET_USD": "1", "LLM_HOURLY_CALL_CAP": "50"},
        "chat",
        0.005,
        None,
        5,
    ),
    "family_ok_global_over_books_family": (
        DEV | {"LLM_DAILY_BUDGET_USD": "0.001", "LLM_HOURLY_CALL_CAP": "50"},
        "chat",
        1.0,
        {sg._usd_key(B): "5000"},
        2,
    ),
    "family_ok_hourly_over_books_family": (
        DEV | {"LLM_DAILY_BUDGET_USD": "1", "LLM_HOURLY_CALL_CAP": "1"},
        "chat",
        1.0,
        None,
        3,
    ),
    "family_only_global_off": (PROD, "chat", 0.005, None, 4),
    "family_without_budget_is_ignored": (
        DEV | {"LLM_DAILY_BUDGET_USD": "1", "LLM_HOURLY_CALL_CAP": "50"},
        "chat",
        0.0,
        None,
        2,
    ),
    "prod_defaults_unlimited": (PROD, "", 0, None, 3),
    "prod_with_caps": (
        PROD | {"LLM_DAILY_BUDGET_USD": "0.005", "LLM_HOURLY_CALL_CAP": "2"},
        "",
        0,
        None,
        4,
    ),
    "custom_estimate": (
        DEV
        | {
            "LLM_DAILY_BUDGET_USD": "0.01",
            "LLM_GUARD_EST_USD_PER_CALL": "0.004",
            "LLM_HOURLY_CALL_CAP": "0",
        },
        "",
        0,
        None,
        4,
    ),
    "paid_calls_disabled": (
        {"ENVIRONMENT": "development", "LLM_DAILY_BUDGET_USD": "1"},
        "chat",
        1.0,
        None,
        2,
    ),
}


def _force_sequential(monkeypatch):
    monkeypatch.setattr(sg, "_admit_scripted", lambda *a, **k: False)


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_scripted_admission_matches_sequential(monkeypatch, name):
    env, family, fam_budget, seed, calls = SCENARIOS[name]

    seq = _setup(monkeypatch, env, fam_budget, seed)
    with monkeypatch.context() as m:
        _force_sequential(m)
        expected = _run(calls, family)
    expected_state = _dump(seq)

    new = _setup(monkeypatch, env, fam_budget, seed)
    got = _run(calls, family)
    assert got == expected
    assert _dump(new) == expected_state


def test_scenario_table_covers_every_decision(monkeypatch):
    seen = set()
    for env, family, fam_budget, seed, calls in SCENARIOS.values():
        _setup(monkeypatch, env, fam_budget, seed)
        for outcome in _run(calls, family):
            seen.add(
                outcome.split(":")[0] + ":" + outcome.split(":")[1]
                if ":" in outcome
                else outcome
            )
    assert seen >= {
        "ok",
        "LLMBudgetExceeded:hourly_cap",
        "LLMBudgetExceeded:daily_budget",
        "LLMBudgetExceeded:family_daily_budget",
        "PaidLLMCallsDisabled:paid_calls_disabled",
    }


def test_admission_is_one_round_trip(monkeypatch):
    r = _setup(
        monkeypatch,
        DEV | {"LLM_DAILY_BUDGET_USD": "10", "LLM_HOURLY_CALL_CAP": "100"},
        5.0,
        None,
    )
    sg.admit_paid_call("t", family="x")
    r.round_trips = 0
    sg.admit_paid_call("t", family="x")
    assert r.round_trips == 1


def test_admission_without_family_is_one_round_trip(monkeypatch):
    r = _setup(
        monkeypatch,
        DEV | {"LLM_DAILY_BUDGET_USD": "10", "LLM_HOURLY_CALL_CAP": "100"},
        0,
        None,
    )
    sg.admit_paid_call("t")
    r.round_trips = 0
    sg.admit_paid_call("t")
    assert r.round_trips == 1


def test_booking_is_one_pipeline_and_adjusts_both_counters(monkeypatch):
    env = DEV | {
        "LLM_DAILY_BUDGET_USD": "10",
        "LLM_HOURLY_CALL_CAP": "100",
        "LLM_GUARD_EST_USD_PER_CALL": "0.002",
    }
    r = _setup(monkeypatch, env, 5.0, None)
    sg.admit_paid_call("t", family="x")
    r.round_trips = 0
    sg.record_actual_usd(0.01, family="x")
    assert r.round_trips == 1
    assert r.get(sg._usd_key(B)) == str(2000 + 8000)
    assert r.get(sg._family_usd_key("x", B)) == str(2000 + 8000)
    assert r.ttl(sg._usd_key(B)) == 3600 * 25

    r.round_trips = 0
    sg.record_usd(0.01, family="x")
    assert r.round_trips == 1
    assert r.get(sg._usd_key(B)) == str(10000 + 10000)
    assert r.get(sg._family_usd_key("x", B)) == str(10000 + 10000)

    r.round_trips = 0
    sg.record_usd(0.01, family="x", include_global=False)
    assert r.round_trips == 1
    assert r.get(sg._usd_key(B)) == str(20000)
    assert r.get(sg._family_usd_key("x", B)) == str(20000 + 10000)


def test_headroom_reads_both_in_one_round_trip(monkeypatch):
    env = DEV | {"LLM_DAILY_BUDGET_USD": "0.01"}
    r = _setup(monkeypatch, env, 0.005, {sg._family_usd_key("x", B): "5000"})
    r.round_trips = 0
    assert sg.session_headroom("x") == sg.HEADROOM_FAMILY_OVER
    assert r.round_trips == 1
    r.set(sg._usd_key(B), "10000")
    assert sg.session_headroom("x") == sg.HEADROOM_GLOBAL_OVER


class _Down:
    def register_script(self, src):
        raise ConnectionError("down")

    def pipeline(self, **kw):
        raise ConnectionError("down")

    def incr(self, k):
        raise ConnectionError("down")


def test_redis_down_prod_fails_open_nonprod_fails_closed(monkeypatch):
    for k, v in (
        PROD | {"LLM_DAILY_BUDGET_USD": "1", "LLM_HOURLY_CALL_CAP": "5"}
    ).items():
        monkeypatch.setenv(k, v)
    sg.set_redis_factory(_Down)
    sg.admit_paid_call("t")
    sg.record_actual_usd(0.5)
    sg.record_usd(0.5)
    assert sg.session_headroom() == sg.HEADROOM_OK

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("LLM_ALLOW_PAID_CALLS", "true")
    with pytest.raises(sg.LLMGuardUnavailable):
        sg.admit_paid_call("t")
    assert sg.session_headroom() == sg.HEADROOM_UNAVAILABLE


def test_script_rejected_by_store_falls_back_to_sequential(monkeypatch):
    from redis.exceptions import ResponseError

    env = DEV | {"LLM_DAILY_BUDGET_USD": "1", "LLM_HOURLY_CALL_CAP": "2"}
    r = _setup(monkeypatch, env, 0, None)

    def boom(src):
        def call(**kw):
            raise ResponseError("CROSSSLOT")

        return call

    monkeypatch.setattr(r, "register_script", boom)
    sg.admit_paid_call("t")
    sg.admit_paid_call("t")
    with pytest.raises(sg.LLMBudgetExceeded) as ei:
        sg.admit_paid_call("t")
    assert ei.value.reason == "hourly_cap"


def _script_error(monkeypatch, r):
    from redis.exceptions import ResponseError

    calls = {"n": 0}

    def boom(src):
        def call(**kw):
            calls["n"] += 1
            raise ResponseError(
                "Error running script (call to f_x): @user_script:1: WRONGTYPE"
            )

        return call

    monkeypatch.setattr(r, "register_script", boom)
    return calls


def test_an_error_inside_the_script_does_not_book_again_sequentially(monkeypatch):
    env = DEV | {"LLM_DAILY_BUDGET_USD": "1", "LLM_HOURLY_CALL_CAP": "2"}
    r = _setup(monkeypatch, env, 0, None)
    _script_error(monkeypatch, r)
    with pytest.raises(sg.LLMGuardUnavailable):
        sg.admit_paid_call("t")
    assert r.get(sg._calls_key(sg._bucket(sg._clock()))) is None


def test_an_error_inside_the_script_fails_open_in_production(monkeypatch):
    env = DEV | {
        "ENVIRONMENT": "production",
        "LLM_DAILY_BUDGET_USD": "1",
        "LLM_HOURLY_CALL_CAP": "2",
    }
    r = _setup(monkeypatch, env, 0, None)
    _script_error(monkeypatch, r)
    sg.admit_paid_call("t")
    assert r.get(sg._calls_key(sg._bucket(sg._clock()))) is None
