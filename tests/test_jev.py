import asyncio

import httpx
import pytest

from kielo_shared import jev
from kielo_shared.llm import spend_guard

QS: list[jev.Question] = [
    {"id": "ok", "kind": "truth", "prompt": "Is the key correct?"}
]


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def spend(monkeypatch):
    calls = {"admit": [], "actual": []}
    monkeypatch.setattr(
        spend_guard, "admit_paid_call", lambda *a, **k: calls["admit"].append((a, k))
    )
    monkeypatch.setattr(
        spend_guard,
        "record_actual_usd",
        lambda usd, **k: calls["actual"].append((usd, k)),
    )
    return calls


def client(handler, **kw):
    return jev.JevClient(
        api_key="k",
        base_url="http://jev.test",
        transport=httpx.MockTransport(handler),
        **kw,
    )


def test_no_key_returns_none_without_calling(monkeypatch):
    monkeypatch.delenv("JEV_API_KEY", raising=False)
    monkeypatch.setenv("JEV_BASE_URL", "http://jev.test")
    assert run(jev.decide("text", QS, site="s")) is None


def test_happy_path_and_spend_booking(spend):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["authorization"]
        seen["path"] = request.url.path
        return httpx.Response(
            200,
            json={
                "model": "jev-1",
                "usage": {"input_tokens": 500000},
                "answers": {"ok": {"value": 0.9, "confidence": 0.8}},
            },
        )

    out = run(
        client(handler, usd_per_mtok=2.0).decide("text", QS, site="exercise_publish")
    )
    assert out == {"ok": jev.Answer(0.9, 0.8)}
    assert seen == {"auth": "Bearer k", "path": jev.PATH}
    assert spend["admit"][0][1]["family"] == "jev_exercise_publish"
    assert spend["actual"] == [(1.0, {"family": "jev_exercise_publish"})]


def test_error_status_returns_none_and_books_nothing(spend):
    out = run(client(lambda r: httpx.Response(500)).decide("t", QS, site="s"))
    assert out is None
    assert spend["actual"] == []


def test_timeout_returns_none(spend):
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    assert run(client(handler).decide("t", QS, site="s")) is None


def test_bad_body_returns_none(spend):
    assert (
        run(
            client(lambda r: httpx.Response(200, json={"nope": 1})).decide(
                "t", QS, site="s"
            )
        )
        is None
    )


def test_spend_refused_returns_none_without_calling(monkeypatch):
    def refuse(*a, **k):
        raise spend_guard.LLMBudgetExceeded("over", reason="family_daily_budget")

    monkeypatch.setattr(spend_guard, "admit_paid_call", refuse)
    hits = []

    def handler(request):
        hits.append(1)
        return httpx.Response(200, json={"answers": {}})

    assert run(client(handler).decide("t", QS, site="s")) is None
    assert hits == []


def test_from_env_timeout(monkeypatch):
    monkeypatch.setenv("JEV_TIMEOUT_S", "0.25")
    assert jev.JevClient.from_env().timeout_s == 0.25
    monkeypatch.delenv("JEV_TIMEOUT_S")
    assert jev.JevClient.from_env().timeout_s == jev.DEFAULT_TIMEOUT_S


def test_shadow_enabled(monkeypatch):
    monkeypatch.setenv("JEV_SHADOW_EXERCISE_PUBLISH", "1")
    monkeypatch.delenv("JEV_API_KEY", raising=False)
    assert not jev.shadow_enabled("exercise_publish")
    monkeypatch.setenv("JEV_API_KEY", "k")
    assert jev.shadow_enabled("exercise_publish")


def test_fake():
    fake = jev.FakeJev({"ok": jev.Answer(1.0, 0.9)})
    out = run(
        fake.decide("t", QS + [{"id": "x", "kind": "score", "prompt": "p"}], site="s")
    )
    assert out == {"ok": jev.Answer(1.0, 0.9)} and fake.calls == 1
