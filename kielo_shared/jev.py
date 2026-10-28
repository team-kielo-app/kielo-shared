"""Thin client for TypeSafe AI's Jev ("System One") model.

Jev writes no text: it answers typed questions about text or JSON with a choice,
a score or a 0-1 truth value, each with a calibrated confidence. Every failure
(no key, spend refused, timeout, error) returns None so the caller falls back to
its current check. Nothing here raises into the caller, and the state text is
never logged.

Wire shape per https://docs.typesafe.ai:

    POST {JEV_BASE_URL}/v1/systemone    Authorization: Bearer {JEV_API_KEY}
    {"state": <str|json>, "model": "jev-1.14.0",
     "questions": {"<id>": {"type": "choice|score|noul", "instructions": "...",
                            "criteria": {...}|[...]}}}
    -> {"model", "usage": {"input_tokens", "output_tokens"}, "answers": {"<id>": ...}}

A truth question is sent as type "noul" and answers with a probability and no
confidence (Answer.confidence is None); never invent one.

Env: JEV_API_KEY, JEV_BASE_URL (default https://api.typesafe.ai), JEV_MODEL (default
jev-1.14.0, pinned), JEV_TIMEOUT_S (default 1.5), JEV_USD_PER_MTOK (input price
booked on the spend guard, default 0.042; output tokens are free),
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
DEFAULT_USD_PER_MTOK = 0.042
DEFAULT_BASE_URL = "https://api.typesafe.ai"
DEFAULT_MODEL = "jev-1.14.0"

Kind = Literal["choice", "score", "truth"]


class Question(TypedDict, total=False):
    id: str
    kind: Kind
    prompt: str
    options: list[str]
    descriptions: dict[str, str]


@dataclass(frozen=True)
class Answer:
    """value: chosen option (choice), number (score) or p(yes) (truth).
    confidence is None for a truth question: Jev gives none."""

    value: Any
    confidence: float | None = None
    probabilities: dict[str, float] | None = None

    @property
    def conf(self) -> float:
        """Confidence, or the truth probability itself when there is none."""
        if self.confidence is not None:
            return self.confidence
        return float(self.value) if isinstance(self.value, (int, float)) else 0.0


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


def _wire_question(q: Question) -> dict[str, Any]:
    kind = q.get("kind", "choice")
    out: dict[str, Any] = {"instructions": q["prompt"]}
    options = list(q.get("options") or [])
    if kind == "truth":
        out["type"] = "noul"
    elif kind == "score":
        out["type"], out["criteria"] = "score", options
    else:
        desc = q.get("descriptions") or {}
        out["type"] = "choice"
        out["criteria"] = {o: desc.get(o) for o in options}
    return out


def _parse_answer(a: Mapping[str, Any]) -> Answer:
    conf = a.get("confidence")
    probs = a.get("probabilities")
    if "noul" in a:
        return Answer(value=float(a["noul"]))
    value = a["choice"] if "choice" in a else float(a["score"])
    return Answer(
        value=value,
        confidence=None if conf is None else float(conf),
        probabilities=dict(probs) if probs else None,
    )


def _parse(payload: Any) -> tuple[Answers, str, int]:
    answers = {str(qid): _parse_answer(a) for qid, a in payload["answers"].items()}
    usage = payload.get("usage") or {}
    return answers, str(payload.get("model") or ""), int(usage.get("input_tokens") or 0)


@dataclass
class JevClient:
    api_key: str = ""
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    timeout_s: float = DEFAULT_TIMEOUT_S
    usd_per_mtok: float = DEFAULT_USD_PER_MTOK
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> "JevClient":
        return cls(
            api_key=(os.environ.get("JEV_API_KEY") or "").strip(),
            base_url=(os.environ.get("JEV_BASE_URL") or DEFAULT_BASE_URL)
            .strip()
            .rstrip("/"),
            model=(os.environ.get("JEV_MODEL") or "").strip() or DEFAULT_MODEL,
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
                json={
                    "state": state,
                    "model": self.model,
                    "questions": {q["id"]: _wire_question(q) for q in questions},
                },
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
