"""Operator kill-switch client (docs/architecture/kill-switches.md).

Mirrors kielo-shared/opswitch (Go). Reads the whole switch table from
kielo-localization, caches it for ``ttl`` seconds, keeps the last good copy when
the store is unreachable and reads as "on" (fail-open) when no copy was ever
loaded. ``evaluate`` is the pure rule shared with the Go package.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx

KEY_CONVO_CALLS = "convo.calls"
KEY_DICTIONARY_MINTING = "content.dictionary_minting"
KEY_LLM_GENERATION = "engine.llm_generation"
KEY_KTV_FEED = "ktv.feed"
KEY_PUSH_CAMPAIGNS = "comms.push_campaigns"
KEY_WEB_INGEST = "ingest.web"

CODE_FEATURE_DISABLED = "FEATURE_DISABLED"
DEFAULT_MESSAGE = "This is paused for a moment. Please try again soon."
DEFAULT_TTL_SECONDS = 30.0
_PATH = "/internal/api/v3/localization/operator-switches"
_FETCH_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class Decision:
    off: bool = False
    message: str = ""
    custom: bool = False
    scope_type: str = ""
    scope_value: str = ""


def evaluate(
    rows: list[dict[str, Any]], key: str, language: str = "", platform: str = ""
) -> Decision:
    lang = (language or "").strip().lower()
    plat = (platform or "").strip().lower()
    best = -1
    chosen: dict[str, Any] = {}
    for row in rows:
        if row.get("switch_key") != key or row.get("enabled", True):
            continue
        scope_type, scope_value = row.get("scope_type"), row.get("scope_value", "")
        if scope_type == "language" and lang and scope_value == lang:
            rank = 2
        elif scope_type == "platform" and plat and scope_value == plat:
            rank = 1
        elif scope_type == "global":
            rank = 0
        else:
            continue
        if rank > best:
            best, chosen = rank, row
    if best < 0:
        return Decision()
    text = (chosen.get("message") or "").strip()
    return Decision(
        off=True,
        message=text or DEFAULT_MESSAGE,
        custom=bool(text),
        scope_type=chosen.get("scope_type", ""),
        scope_value=chosen.get("scope_value", ""),
    )


def error_body(key: str, decision: Decision) -> dict[str, Any]:
    """Canonical 503 envelope for a refusal."""
    return {
        "error": {
            "code": CODE_FEATURE_DISABLED,
            "message": decision.message,
            "details": {"switch_key": key, "custom_message": decision.custom},
        },
        "message": decision.message,
    }


class SwitchClient:
    def __init__(
        self,
        base_url: str,
        internal_api_key: str = "",
        ttl: float = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._base_url = (base_url or "").strip().rstrip("/")
        self._api_key = internal_api_key
        self._ttl = ttl if ttl > 0 else DEFAULT_TTL_SECONDS
        self._clock = clock
        self._rows: list[dict[str, Any]] = []
        self._loaded = False
        self._fetched_at = 0.0

    async def check(self, key: str, language: str = "", platform: str = "") -> Decision:
        if not self._base_url:
            return Decision()
        rows = await self._snapshot()
        return evaluate(rows, key, language, platform)

    async def _snapshot(self) -> list[dict[str, Any]]:
        if self._fetched_at and self._clock() - self._fetched_at < self._ttl:
            return self._rows
        # Stamp failures too: an outage costs one short fetch per TTL, not one per call.
        self._fetched_at = self._clock()
        try:
            headers = {"X-Internal-API-Key": self._api_key} if self._api_key else {}
            async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT_SECONDS) as client:
                resp = await client.get(self._base_url + _PATH, headers=headers)
            resp.raise_for_status()
            body = resp.json()
            if isinstance(body.get("data"), dict):
                body = body["data"]
            self._rows, self._loaded = list(body.get("items") or []), True
        except (httpx.HTTPError, ValueError, AttributeError):
            pass
        return self._rows
