"""AI-models control-plane client (docs/architecture/ai-models-control-plane.md).

Mirrors kielo-shared/llmroute (Go). ``resolve(family, default_model)`` answers
the model, thinking budget and daily budget an admin chose for an LLM task
family in kielo-localization. The table is cached for ``ttl`` seconds and
refreshed in the background; the last good copy keeps answering when the store
is unreachable, and with no copy (or no ``LOCALIZATION_SERVICE_URL``) the
caller's compiled default is returned (fail-open, same as opswitch).

A route also answers WHICH provider serves its model (``Route.provider``): the
``llm_models.provider`` of the routed model, fetched alongside the routes. The
same table prices calls (``model_price`` / ``estimate_usd``).

``record_call`` aggregates usage per (service, family, model) in-process and a
daemon thread flushes it to the rollup endpoint every few minutes, best effort.
"""

from __future__ import annotations

import asyncio
import calendar
import dataclasses
import json
import logging
import os
import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx

from kielo_shared.llm import pricing

logger = logging.getLogger(__name__)

FAMILY_JUKA_LIVE = "juka_live"
# The model a live call fails over to (the convo agent uses it when the live
# route's provider errors or is unusable).
FAMILY_JUKA_LIVE_FAILOVER = "juka_live_failover"
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
_MODELS_PATH = "/internal/api/v3/localization/llm-models"
_USAGE_PATH = "/internal/api/v3/localization/llm-usage"
_FETCH_TIMEOUT_SECONDS = 2.0
_RESERVOIR = 512


PROVIDER_GOOGLE = "google"
PROVIDER_OPENAI = "openai"

# Families whose call sites can drive an OpenAI model: the ones served by the
# convo agent's routed_llm / LiveKit builder. Every other family (the engine's
# LangChain Gemini client, ingest, the Go Gemini seam, KTV, hints, translation,
# scenario authoring) can only drive Gemini, so a new family is Gemini-only by
# default and a route naming another provider for it is refused: the caller's
# compiled default runs, with one logged line, instead of a misrouted call.
OPENAI_CAPABLE_FAMILIES = frozenset(
    {
        "juka_live",
        "juka_live_failover",
        "juka_feedback",
        "juka_step_check",
    }
)

SNAPSHOT_TTL_SECONDS = 7 * 24 * 3600

# Last resort when llm_models has no row for a routed model (store down on a
# cold start, model not yet allowlisted): the model-name family decides.
_PROVIDER_BY_PREFIX = (("gemini-", PROVIDER_GOOGLE), ("gpt-", PROVIDER_OPENAI))


@dataclass(frozen=True)
class Route:
    model: str
    thinking_budget: int = THINKING_DEFAULT
    daily_budget_usd: float = 0.0
    provider: str = ""


@dataclass(frozen=True)
class ModelInfo:
    provider: str
    input_usd_per_mtok: float
    output_usd_per_mtok: float
    active: bool = True


def infer_provider(model: str) -> str:
    name = (model or "").strip().lower()
    for prefix, provider in _PROVIDER_BY_PREFIX:
        if name.startswith(prefix):
            return provider
    return ""


def _decode_models(body: Any) -> dict[str, ModelInfo]:
    if isinstance(body, dict) and isinstance(body.get("data"), dict):
        body = body["data"]
    out: dict[str, ModelInfo] = {}
    for row in (body or {}).get("items") or []:
        model = (row.get("model") or "").strip()
        provider = (row.get("provider") or "").strip()
        if not model or not provider:
            continue
        out[model] = ModelInfo(
            provider=provider,
            input_usd_per_mtok=float(row.get("input_usd_per_mtok") or 0.0),
            output_usd_per_mtok=float(row.get("output_usd_per_mtok") or 0.0),
            active=bool(row.get("active", True)),
        )
    return out


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
            provider=(row.get("provider") or "").strip(),
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
        self._models: dict[str, ModelInfo] = {}
        self._models_loaded = False
        self._snapshot_load: Callable[[], dict[str, Any] | None] | None = None
        self._snapshot_save: Callable[[dict[str, Any]], None] | None = None
        self._warned: set[tuple[str, ...]] = set()
        self._loaded = False
        self._fetched_at = 0.0
        self._refreshing = False
        self._lock = threading.Lock()
        self._logged: dict[str, Route] = {}

    def set_snapshot_store(
        self,
        load: Callable[[], dict[str, Any] | None],
        save: Callable[[dict[str, Any]], None],
    ) -> None:
        """Keep a last-good copy of the tables outside the process (Redis), so a
        cold start during a localization outage serves the last good routes."""
        self._snapshot_load, self._snapshot_save = load, save

    def _warn_once(self, *key: str, message: str, args: tuple[Any, ...]) -> None:
        if key in self._warned:
            return
        self._warned.add(key)
        logger.error(message, *args)

    def route(self, family: str) -> Route | None:
        """The stored route, or None when there is none or it cannot be served
        (no store, unknown family, model missing/inactive, provider not allowed)."""
        if not self._base_url:
            return None
        self._maybe_refresh()
        found = self._routes.get(family)
        if found is None:
            return None
        found = self._servable(family, found)
        if found is None:
            return None
        if self._logged.get(family) != found:
            self._logged[family] = found
            logger.info(
                "LLM_ROUTE resolved family=%s model=%s provider=%s thinking_budget=%d daily_budget_usd=%.4f",
                family,
                found.model,
                found.provider,
                found.thinking_budget,
                found.daily_budget_usd,
            )
        return found

    def _servable(self, family: str, route: Route) -> Route | None:
        info = self._models.get(route.model)
        if self._models_loaded:
            if info is None or not info.active:
                reason = "missing from llm_models" if info is None else "inactive"
                self._warn_once(
                    "model",
                    family,
                    route.model,
                    reason,
                    message="LLM_ROUTE family=%s model=%s is %s; using the compiled default",
                    args=(family, route.model, reason),
                )
                return None
            provider = info.provider
        else:
            provider = route.provider or infer_provider(route.model)
            self._warn_once(
                "inferred",
                route.model,
                message="LLM_ROUTE llm_models never loaded; model=%s provider inferred=%s",
                args=(route.model, provider or "unknown"),
            )
        if family not in OPENAI_CAPABLE_FAMILIES and provider != PROVIDER_GOOGLE:
            self._warn_once(
                "provider",
                family,
                route.model,
                message="LLM_ROUTE family=%s can only drive Gemini; route model=%s provider=%s refused, using the compiled default",
                args=(family, route.model, provider or "unknown"),
            )
            return None
        return dataclasses.replace(route, provider=provider)

    def model_info(self, model: str) -> ModelInfo | None:
        if not self._base_url:
            return None
        self._maybe_refresh()
        return self._models.get(model)

    def resolve(
        self,
        family: str,
        default_model: str,
        default_thinking: int = THINKING_DEFAULT,
        default_provider: str = "",
    ) -> Route:
        found = self.route(family)
        if found is None:
            return Route(
                default_model,
                default_thinking,
                0.0,
                default_provider or infer_provider(default_model),
            )
        return found

    def _maybe_refresh(self) -> None:
        now = self._clock()
        fresh = self._fetched_at and now - self._fetched_at < self._ttl
        if fresh:
            return
        if not self._loaded and not self._fetched_at:
            if not _loop_running():
                self._refresh()
                return
            # Never fetch on the event loop: serve the last-good copy now and
            # refresh in the background.
            self._load_snapshot()
        with self._lock:
            if self._refreshing:
                return
            self._refreshing = True
        threading.Thread(target=self._refresh, daemon=True).start()

    def age_seconds(self) -> float:
        return self._clock() - self._fetched_at if self._fetched_at else float("inf")

    def warm(self) -> None:
        """Fetch now (worker prewarm), so the first session never waits on localization."""
        if self._base_url:
            self._refresh()

    def _get_json(self, path: str, headers: dict[str, str]) -> Any:
        resp = httpx.get(
            self._base_url + path, headers=headers, timeout=_FETCH_TIMEOUT_SECONDS
        )
        resp.raise_for_status()
        return resp.json()

    def _refresh(self) -> None:
        # Stamp failures too: an outage costs one short fetch per TTL, not one per call.
        self._fetched_at = self._clock()
        try:
            headers = {"X-Internal-API-Key": self._api_key} if self._api_key else {}
            routes_body = self._get_json(_ROUTES_PATH, headers)
            self._routes, self._loaded = _decode(routes_body), True
            models_body = None
            try:
                models_body = self._get_json(_MODELS_PATH, headers)
                decoded = _decode_models(models_body)
                self._models = decoded
                # An empty table is not a table: it must not refuse every route.
                self._models_loaded = bool(decoded)
            except (httpx.HTTPError, ValueError, AttributeError):
                pass
            self._save_snapshot(routes_body, models_body)
        except (httpx.HTTPError, ValueError, AttributeError):
            pass
        finally:
            with self._lock:
                self._refreshing = False
        if not self._loaded:
            self._load_snapshot()

    def _save_snapshot(self, routes_body: Any, models_body: Any) -> None:
        if self._snapshot_save is None:
            return
        try:
            snap: dict[str, Any] = {"routes": routes_body}
            if models_body is not None:
                snap["models"] = models_body
            elif self._models_loaded:
                snap["models"] = {
                    "items": [
                        {
                            "model": m,
                            "provider": i.provider,
                            "input_usd_per_mtok": i.input_usd_per_mtok,
                            "output_usd_per_mtok": i.output_usd_per_mtok,
                            "active": i.active,
                        }
                        for m, i in self._models.items()
                    ]
                }
            self._snapshot_save(snap)
        except Exception as exc:
            logger.warning("LLM_ROUTE snapshot save failed: %s", exc)

    def _load_snapshot(self) -> None:
        if self._snapshot_load is None:
            return
        try:
            snap = self._snapshot_load()
            if not snap:
                return
            self._routes = _decode(snap.get("routes"))
            self._loaded = True
            if snap.get("models") is not None:
                self._models = _decode_models(snap["models"])
                self._models_loaded = bool(self._models)
            logger.warning(
                "LLM_ROUTE localization unreachable; serving the last-good snapshot (%d routes)",
                len(self._routes),
            )
        except Exception as exc:
            logger.warning("LLM_ROUTE snapshot load failed: %s", exc)


def _loop_running() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


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


def warm() -> None:
    """Prefetch the route tables (call from worker prewarm, off the event loop)."""
    if _client is not None:
        _client.warm()


def set_snapshot_store(
    load: Callable[[], dict[str, Any] | None],
    save: Callable[[dict[str, Any]], None],
) -> None:
    """Install a last-good snapshot store on the process-wide client (see RouteClient)."""
    if _client is not None:
        _client.set_snapshot_store(load, save)


async def refresh_if_stale(
    max_age_seconds: float = 300.0, wait_seconds: float = 2.5
) -> None:
    """Before building a session: if the route tables are older than max_age
    (a prewarmed idle process can be minutes old, and the background refresh is
    best effort), refresh them on a worker thread, waiting a bounded time."""
    client = _client
    if client is None or not client._base_url:
        return
    if client.age_seconds() <= max_age_seconds:
        return
    try:
        await asyncio.wait_for(asyncio.to_thread(client.warm), timeout=wait_seconds)
    except (asyncio.TimeoutError, Exception) as exc:
        logger.warning("LLM_ROUTE stale refresh skipped: %s", type(exc).__name__)


def snapshot_json_store(
    client: Any, key: str
) -> tuple[Callable[[], Any], Callable[[Any], None]]:
    """Load/save callables over a sync redis-like client (get/set with ex)."""

    def load() -> dict[str, Any] | None:
        raw = client.get(key)
        return json.loads(raw) if raw else None

    def save(snap: dict[str, Any]) -> None:
        client.set(key, json.dumps(snap), ex=SNAPSHOT_TTL_SECONDS)

    return load, save


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
    family: str,
    default_model: str,
    default_thinking: int = THINKING_DEFAULT,
    default_provider: str = "",
) -> Route:
    """The family's model, provider and budgets; the default fills a gap (no store, unknown family)."""
    if _client is None:
        return Route(
            default_model,
            default_thinking,
            0.0,
            default_provider or infer_provider(default_model),
        )
    return _client.resolve(family, default_model, default_thinking, default_provider)


def stored_route(family: str) -> Route | None:
    """The route the store holds for family, None when there is none (no store, unknown family)."""
    return _client.route(family) if _client is not None else None


def model_price(model: str) -> tuple[float, float]:
    """USD per 1M tokens (input, output incl. thinking): llm_models first, then the compiled table."""
    info = _client.model_info(model) if _client is not None else None
    if info is not None:
        return (info.input_usd_per_mtok, info.output_usd_per_mtok)
    return pricing.PRICES.get(model, pricing.FALLBACK_PRICE)


def estimate_usd(
    model: str, tokens_in: int, tokens_out: int, thinking: int = 0
) -> float:
    price_in, price_out = model_price(model)
    return (tokens_in * price_in + (tokens_out + thinking) * price_out) / 1_000_000


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
