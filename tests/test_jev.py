import asyncio
import json

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


def test_happy_path_real_shapes_and_spend(spend):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["authorization"]
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": "jev-1.14.0",
                "usage": {"input_tokens": 500000, "output_tokens": 9},
                "answers": {
                    "ok": {"type": "noul", "noul": 0.9},
                    "sev": {
                        "type": "choice",
                        "choice": "high",
                        "confidence": 0.7,
                        "probabilities": {"low": 0.1, "high": 0.9},
                    },
                    "fit": {
                        "type": "score",
                        "score": 4,
                        "confidence": 0.6,
                        "probabilities": {"4": 0.6},
                    },
                },
            },
        )

    qs: list[jev.Question] = QS + [
        {
            "id": "sev",
            "kind": "choice",
            "prompt": "Severity?",
            "options": ["low", "high"],
            "descriptions": {"low": "minor"},
        },
        {"id": "fit", "kind": "score", "prompt": "Fit?", "options": ["1", "2"]},
    ]
    out = run(client(handler).decide("text", qs, site="exercise_publish"))
    assert out is not None
    assert out["ok"] == jev.Answer(0.9) and out["ok"].confidence is None
    assert out["ok"].conf == 0.9
    assert out["sev"] == jev.Answer("high", 0.7, {"low": 0.1, "high": 0.9})
    assert out["fit"].value == 4.0 and out["fit"].confidence == 0.6
    assert seen["auth"] == "Bearer k" and seen["path"] == jev.PATH
    body = seen["body"]
    assert body["model"] == "jev-1.14.0" and body["state"] == "text"
    assert body["questions"]["ok"] == {
        "type": "noul",
        "instructions": "Is the key correct?",
    }
    assert body["questions"]["sev"]["criteria"] == {"low": "minor", "high": None}
    assert body["questions"]["fit"] == {
        "type": "score",
        "instructions": "Fit?",
        "criteria": ["1", "2"],
    }
    assert spend["admit"][0][1]["family"] == "jev_exercise_publish"
    usd, kw = spend["actual"][0]
    assert abs(usd - 500000 * 0.042 / 1e6) < 1e-9 and kw == {
        "family": "jev_exercise_publish"
    }


def test_rate_limit_returns_none(spend):
    assert run(client(lambda r: httpx.Response(429)).decide("t", QS, site="s")) is None


def test_env_defaults(monkeypatch):
    for n in ("JEV_BASE_URL", "JEV_MODEL", "JEV_USD_PER_MTOK"):
        monkeypatch.delenv(n, raising=False)
    c = jev.JevClient.from_env()
    assert (c.base_url, c.model, c.usd_per_mtok) == (
        "https://api.typesafe.ai",
        "jev-1.14.0",
        0.042,
    )
    monkeypatch.setenv("JEV_MODEL", "jev-9")
    assert jev.JevClient.from_env().model == "jev-9"


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
