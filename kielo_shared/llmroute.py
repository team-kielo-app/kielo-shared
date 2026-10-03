"""AI-models control-plane client (docs/architecture/ai-models-control-plane.md).

Mirrors kielo-shared/llmroute (Go). ``resolve(family, default_model)`` answers
the model, thinking budget and daily budget an admin chose for an LLM task
family in kielo-localization. The table is cached for ``ttl`` seconds and
refreshed in the background; the last good copy keeps answering when the store
is unreachable, and with no copy (or no ``LOCALIZATION_SERVICE_URL``) the
caller's compiled default is returned (fail-open, same as opswitch).

``record_call`` aggregates usage per (service, family, model) in-process and a
daemon thread flushes it to the rollup endpoint every few minutes, best effort.
"""

from __future__ import annotations

import calendar
import logging
import os
import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx

logger = logging.getLogger(__name__)

FAMILY_JUKA_LIVE = "juka_live"
FAMILY_JUKA_FEEDBACK = "juka_feedback"
FAMILY_JUKA_STEP_CHECK = "juka_step_check"
FAMILY_JUKA_HINTS = "juka_hints"
FAMILY_JUKA_TRANSLATION = "juka_translation"
FAMILY_SCENARIO_AUTHORING = "scenario_authoring"
FAMILY_EXERCISE_GENERATION = "exercise_generation"
FAMILY_EXERCISE_CONTEXT_GENERATION = "exercise_context_generation"
FAMILY_EXERCISE_JUDGE = "exercise_judge"
FAMILY_EXERCISE_REVIEW = "exercise_review"
FAMILY_TRANSLATION_BATCH = "translation_batch"
FAMILY_CONTENT_INGEST = "content_ingest"
FAMILY_WEB_INGEST = "web_ingest"
FAMILY_KTV_AI = "ktv_ai"

THINKING_DEFAULT = -1
DEFAULT_TTL_SECONDS = 30.0
DEFAULT_FLUSH_SECONDS = 300.0
_ROUTES_PATH = "/internal/api/v3/localization/llm-routes"
_USAGE_PATH = "/internal/api/v3/localization/llm-usage"
_FETCH_TIMEOUT_SECONDS = 2.0
_RESERVOIR = 512


@dataclass(frozen=True)
class Route:
    model: str
    thinking_budget: int = THINKING_DEFAULT
    daily_budget_usd: float = 0.0


def _decode(body: Any) -> dict[str, Route]:
    if isinstance(body, dict) and isinstance(body.get("data"), dict):
        body = body["data"]
    out: dict[str, Route] = {}
    for row in (body or {}).get("items") or []:
        family, model = row.get("family"), (row.get("model") or "").strip()
        if not family or not model:
            continue
        budget = row.get("daily_budget_usd")
        out[family] = Route(
            model=model,
            thinking_budget=int(row.get("thinking_budget", THINKING_DEFAULT)),
            daily_budget_usd=float(budget) if budget is not None else 0.0,
        )
    return out


class RouteClient:
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
        self._routes: dict[str, Route] = {}
        self._loaded = False
        self._fetched_at = 0.0
        self._refreshing = False
        self._lock = threading.Lock()
        self._logged: dict[str, Route] = {}

    def route(self, family: str) -> Route | None:
        """The stored route, or None when there is none (no store, unknown family)."""
        if not self._base_url:
            return None
        self._maybe_refresh()
        found = self._routes.get(family)
        if found is not None and self._logged.get(family) != found:
            self._logged[family] = found
            logger.info(
                "LLM_ROUTE resolved family=%s model=%s thinking_budget=%d daily_budget_usd=%.4f",
                family,
                found.model,
                found.thinking_budget,
                found.daily_budget_usd,
            )
        return found

    def resolve(
        self,
        family: str,
        default_model: str,
        default_thinking: int = THINKING_DEFAULT,
    ) -> Route:
        found = self.route(family)
        if found is None:
            return Route(default_model, default_thinking, 0.0)
        return found

    def _maybe_refresh(self) -> None:
        now = self._clock()
        fresh = self._fetched_at and now - self._fetched_at < self._ttl
        if fresh:
            return
        if not self._loaded and not self._fetched_at:
            self._refresh()
            return
        with self._lock:
            if self._refreshing:
                return
            self._refreshing = True
        threading.Thread(target=self._refresh, daemon=True).start()

    def _refresh(self) -> None:
        # Stamp failures too: an outage costs one short fetch per TTL, not one per call.
        self._fetched_at = self._clock()
        try:
            headers = {"X-Internal-API-Key": self._api_key} if self._api_key else {}
            resp = httpx.get(
                self._base_url + _ROUTES_PATH,
                headers=headers,
                timeout=_FETCH_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            self._routes, self._loaded = _decode(resp.json()), True
        except (httpx.HTTPError, ValueError, AttributeError):
            pass
        finally:
            with self._lock:
                self._refreshing = False


class _Agg:
    __slots__ = (
        "calls",
        "inp",
        "out",
        "thinking",
        "usd",
        "errors",
        "retries",
        "lat",
        "seen",
    )

    def __init__(self) -> None:
        self.calls = self.inp = self.out = self.thinking = 0
        self.errors = self.retries = self.seen = 0
        self.usd = 0.0
        self.lat: list[int] = []


def _percentile(values: list[int], p: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, int(p * len(ordered) + 0.5) - 1))
    return ordered[idx]


class UsageRecorder:
    def __init__(
        self,
        service: str,
        base_url: str,
        internal_api_key: str = "",
        flush_seconds: float = DEFAULT_FLUSH_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._service = service
        self._base_url = (base_url or "").strip().rstrip("/")
        self._api_key = internal_api_key
        self._flush_seconds = flush_seconds
        self._clock = clock
        self._aggs: dict[tuple[int, str, str, str], _Agg] = {}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    @property
    def enabled(self) -> bool:
        return bool(self._base_url)

    def record(
        self,
        family: str,
        model: str,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        thinking_tokens: int = 0,
        usd: float = 0.0,
        latency_ms: float = 0.0,
        error: bool = False,
        retries: int = 0,
    ) -> None:
        if not self.enabled or not family:
            return
        hour = int(self._clock() // 3600) * 3600
        with self._lock:
            agg = self._aggs.setdefault((hour, self._service, family, model), _Agg())
            agg.calls += 1
            agg.inp += int(input_tokens)
            agg.out += int(output_tokens)
            agg.thinking += int(thinking_tokens)
            agg.usd += float(usd)
            agg.errors += 1 if error else 0
            agg.retries += int(retries)
            agg.seen += 1
            ms = int(latency_ms)
            if len(agg.lat) < _RESERVOIR:
                agg.lat.append(ms)
            else:
                j = random.randrange(agg.seen)
                if j < _RESERVOIR:
                    agg.lat[j] = ms
        self._ensure_thread()

    def drain(self) -> list[dict[str, Any]]:
        with self._lock:
            aggs, self._aggs = self._aggs, {}
        rows = []
        for (hour, service, family, model), a in aggs.items():
            rows.append(
                {
                    "hour": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(hour)),
                    "service": service,
                    "family": family,
                    "model": model,
                    "calls": a.calls,
                    "input_tokens": a.inp,
                    "output_tokens": a.out,
                    "thinking_tokens": a.thinking,
                    "usd": round(a.usd, 8),
                    "errors": a.errors,
                    "retries": a.retries,
                    "latency_ms_p50": _percentile(a.lat, 0.50),
                    "latency_ms_p95": _percentile(a.lat, 0.95),
                }
            )
        return rows

    def flush(self) -> bool:
        """Post the accumulated rows; on failure they are counted again next flush."""
        rows = self.drain()
        if not rows:
            return True
        try:
            headers = {"X-Internal-API-Key": self._api_key} if self._api_key else {}
            resp = httpx.post(
                self._base_url + _USAGE_PATH,
                json={"rows": rows},
                headers=headers,
                timeout=_FETCH_TIMEOUT_SECONDS * 1.5,
            )
            resp.raise_for_status()
            return True
        except (httpx.HTTPError, ValueError):
            self._restore(rows)
            return False

    def _restore(self, rows: list[dict[str, Any]]) -> None:
        with self._lock:
            for r in rows:
                hour = calendar.timegm(time.strptime(r["hour"], "%Y-%m-%dT%H:%M:%SZ"))
                agg = self._aggs.setdefault(
                    (hour, r["service"], r["family"], r["model"]), _Agg()
                )
                agg.calls += r["calls"]
                agg.inp += r["input_tokens"]
                agg.out += r["output_tokens"]
                agg.thinking += r["thinking_tokens"]
                agg.usd += r["usd"]
                agg.errors += r["errors"]
                agg.retries += r["retries"]

    def _ensure_thread(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(
                target=self._loop, daemon=True, name="llm-usage-flush"
            )
            self._thread.start()

    def _loop(self) -> None:
        while True:
            time.sleep(self._flush_seconds)
            try:
                self.flush()
            except Exception as exc:  # never let the flusher die
                logger.warning("LLM_USAGE flush failed: %s", exc)


_client: RouteClient | None = None
_recorder: UsageRecorder | None = None
_service = ""


def configure(service: str, base_url: str, internal_api_key: str = "") -> None:
    """Install the process-wide client + recorder. Empty base_url leaves every family on its default."""
    global _client, _recorder, _service
    _service = service
    _client = RouteClient(base_url, internal_api_key)
    _recorder = UsageRecorder(service, base_url, internal_api_key)


def configure_from_env(service: str) -> None:
    key = (
        os.environ.get("KIELO_INTERNAL_API_KEY")
        or os.environ.get("INTERNAL_API_KEY")
        or ""
    )
    configure(service, os.environ.get("LOCALIZATION_SERVICE_URL", ""), key)


def set_client_for_test(
    client: RouteClient | None, recorder: UsageRecorder | None = None
) -> None:
    global _client, _recorder
    _client, _recorder = client, recorder


def service_name() -> str:
    return _service


def resolve(
    family: str, default_model: str, default_thinking: int = THINKING_DEFAULT
) -> Route:
    if _client is None:
        return Route(default_model, default_thinking, 0.0)
    return _client.resolve(family, default_model, default_thinking)


def daily_budget_usd(family: str) -> float:
    """The family's per-day cap in USD; 0 when there is none or no store."""
    found = _client.route(family) if _client is not None else None
    return found.daily_budget_usd if found is not None else 0.0


def record_call(family: str, model: str, **kwargs: Any) -> None:
    """Add one finished call to the process-wide rollup. Never raises."""
    if _recorder is None:
        return
    try:
        _recorder.record(family, model, **kwargs)
    except Exception as exc:
        logger.debug("LLM_USAGE record skipped: %s", exc)
