"""Thin client for TypeSafe AI's Jev ("System One") model.

Jev writes no text: it answers typed questions about text or JSON with a choice,
a score or a 0-1 truth value, each with a calibrated confidence. Every failure
(no key, spend refused, timeout, error) returns None so the caller falls back to
its current check. Nothing here raises into the caller, and the state text is
never logged.

PROVISIONAL WIRE SHAPE: TypeSafe's request and response are not documented
anywhere we can read. The shape below is our own minimal typed contract and must
be reconciled with the real API before any call site relies on it.

    POST {JEV_BASE_URL}/v1/systemone    Authorization: Bearer {JEV_API_KEY}
    {"state": <str|json>, "questions": [{"id","kind","prompt","options"?}]}
    -> {"model": "...", "usage": {"input_tokens": N},
        "answers": {"<id>": {"value": ..., "confidence": 0-1}}}

Env: JEV_API_KEY, JEV_BASE_URL, JEV_TIMEOUT_S (default 1.5),
JEV_USD_PER_MTOK (provisional input price booked on the spend guard, default 1.0),
JEV_SHADOW_<SITE>=1 (see ``shadow_enabled``).
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Literal, Mapping, Sequence, TypedDict

import httpx

from kielo_shared.llm import spend_guard

logger = logging.getLogger(__name__)

PATH = "/v1/systemone"
FAMILY_PREFIX = "jev_"
DEFAULT_TIMEOUT_S = 1.5
DEFAULT_USD_PER_MTOK = 1.0

Kind = Literal["choice", "score", "truth"]


class Question(TypedDict, total=False):
    id: str
    kind: Kind
    prompt: str
    options: list[str]


@dataclass(frozen=True)
class Answer:
    value: Any
    confidence: float


Answers = dict[str, Answer]


def family(site: str) -> str:
    return f"{FAMILY_PREFIX}{site}"


def _float_env(name: str, default: float) -> float:
    try:
        value = float((os.environ.get(name) or "").strip())
    except ValueError:
        return default
    return value if value > 0 else default


def shadow_enabled(site: str) -> bool:
    """True only when JEV_SHADOW_<SITE>=1 and a key is set."""
    flag = (os.environ.get(f"JEV_SHADOW_{site.upper()}") or "").strip()
    return flag == "1" and bool((os.environ.get("JEV_API_KEY") or "").strip())


def _parse(payload: Any) -> tuple[Answers, str, int]:
    raw = payload["answers"]
    answers = {
        str(qid): Answer(value=a["value"], confidence=float(a["confidence"]))
        for qid, a in raw.items()
    }
    usage = payload.get("usage") or {}
    return answers, str(payload.get("model") or ""), int(usage.get("input_tokens") or 0)


@dataclass
class JevClient:
    api_key: str = ""
    base_url: str = ""
    timeout_s: float = DEFAULT_TIMEOUT_S
    usd_per_mtok: float = DEFAULT_USD_PER_MTOK
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> "JevClient":
        return cls(
            api_key=(os.environ.get("JEV_API_KEY") or "").strip(),
            base_url=(os.environ.get("JEV_BASE_URL") or "").strip().rstrip("/"),
            timeout_s=_float_env("JEV_TIMEOUT_S", DEFAULT_TIMEOUT_S),
            usd_per_mtok=_float_env("JEV_USD_PER_MTOK", DEFAULT_USD_PER_MTOK),
        )

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.base_url)

    async def decide(
        self,
        state: str | Mapping[str, Any],
        questions: Sequence[Question],
        *,
        site: str,
    ) -> Answers | None:
        if not self.enabled or not questions:
            return None
        try:
            return await self._decide(state, questions, site)
        except Exception as exc:
            logger.warning(
                "jev: call failed site=%s error=%s", site, type(exc).__name__
            )
            return None

    async def _decide(
        self, state: str | Mapping[str, Any], questions: Sequence[Question], site: str
    ) -> Answers | None:
        fam = family(site)
        try:
            spend_guard.admit_paid_call("jev", provider="jev", family=fam)
        except spend_guard.PaidLLMCallRefused as exc:
            logger.warning("jev: spend refused site=%s reason=%s", site, exc.reason)
            return None
        started = time.perf_counter()
        async with httpx.AsyncClient(
            timeout=self.timeout_s, transport=self.transport
        ) as http:
            resp = await http.post(
                self.base_url + PATH,
                json={"state": state, "questions": list(questions)},
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
        latency_ms = int((time.perf_counter() - started) * 1000)
        resp.raise_for_status()
        answers, model, input_tokens = _parse(resp.json())
        spend_guard.record_actual_usd(
            input_tokens * self.usd_per_mtok / 1e6, family=fam
        )
        logger.info(
            "jev: decided site=%s model=%s latency_ms=%d input_tokens=%d",
            site,
            model,
            latency_ms,
            input_tokens,
        )
        return answers


async def decide(
    state: str | Mapping[str, Any],
    questions: Sequence[Question],
    *,
    site: str,
) -> Answers | None:
    """Ask Jev typed questions about ``state``; None on no key, refusal, timeout or error."""
    return await JevClient.from_env().decide(state, questions, site=site)


class FakeJev:
    """Canned answers keyed by question id; ids it has no answer for are omitted."""

    def __init__(self, canned: Mapping[str, Answer]) -> None:
        self.canned = dict(canned)
        self.calls = 0

    async def decide(
        self,
        state: str | Mapping[str, Any],
        questions: Sequence[Question],
        *,
        site: str,
    ) -> Answers | None:
        self.calls += 1
        return {
            q["id"]: self.canned[q["id"]] for q in questions if q["id"] in self.canned
        }


__all__ = [
    "Answer",
    "Answers",
    "FakeJev",
    "JevClient",
    "Question",
    "decide",
    "family",
    "shadow_enabled",
]
