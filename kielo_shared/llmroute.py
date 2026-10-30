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

A route may carry a candidate (model, thinking budget, share): ``resolve`` sends
``share`` percent of keys to the candidate (``Route.variant == "candidate"``), the
same key always to the same model. ``record_call`` aggregates usage per (service,
family, model) in-process, with the call's outcome and whether the compiled
default ran in place of a refused route; ``record_outcome`` adds accepted /
rejected counts for what a caller checked. A daemon thread flushes the rollup to
the endpoint every few minutes, best effort, and ``allow_providers`` /
``configure_from_env`` tell localization which providers this service can drive.
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
import zlib
from dataclasses import dataclass
from typing import Any, Callable, Iterable

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
_CAPABILITIES_PATH = "/internal/api/v3/localization/llm-capabilities"
_CAPABILITY_DELAY_SECONDS = 1.0
_FETCH_TIMEOUT_SECONDS = 2.0
_RESERVOIR = 512


VARIANT_ROUTE = "route"
VARIANT_CANDIDATE = "candidate"

OUTCOME_OK = "ok"
OUTCOME_ERROR = "error"
OUTCOME_REFUSED = "refused"
OUTCOME_INVALID_OUTPUT = "invalid_output"
OUTCOMES = frozenset(
    {OUTCOME_OK, OUTCOME_ERROR, OUTCOME_REFUSED, OUTCOME_INVALID_OUTPUT}
)
# A call that returned nothing usable because the provider failed or declined
# counts under `errors`; invalid_output is the caller's quality verdict and is
# counted through record_outcome, not here.
_ERROR_OUTCOMES = frozenset({OUTCOME_ERROR, OUTCOME_REFUSED})

PROVIDER_GOOGLE = "google"
PROVIDER_OPENAI = "openai"
PROVIDER_ANTHROPIC = "anthropic"

# Families whose call sites can drive an OpenAI model in a process that declares
# nothing: the ones served by the convo agent's routed_llm / LiveKit builder.
# Every process can drive Gemini. A process whose call sites can drive more
# declares it with allow_providers (the engine's llm_providers drive OpenAI and
# Claude for every family); a route naming a provider the process cannot drive
# is refused and the caller's compiled default runs, with one logged line,
# instead of a misrouted call.
OPENAI_CAPABLE_FAMILIES = frozenset(
    {
        "juka_live",
        "juka_live_failover",
        "juka_feedback",
        "juka_step_check",
    }
)

# provider -> the families this process can drive it for (None: every family).
_DRIVABLE: dict[str, frozenset[str] | None] = {PROVIDER_OPENAI: OPENAI_CAPABLE_FAMILIES}


def allow_providers(
    providers: Iterable[str], families: Iterable[str] | None = None
) -> None:
    """Declare that this process's call sites can drive `providers`, for
    `families` or (None) for every family. Call at start-up; the declaration is
    also reported to localization (a background thread, best effort)."""
    scoped = None if families is None else frozenset(families)
    for provider in providers:
        current = _DRIVABLE.get(provider, frozenset())
        if scoped is None or current is None:
            _DRIVABLE[provider] = None
        else:
            _DRIVABLE[provider] = current | scoped
    _queue_capability_report()


def can_drive(family: str, provider: str) -> bool:
    if provider == PROVIDER_GOOGLE:
        return True
    families = _DRIVABLE.get(provider, frozenset())
    return families is None or family in families


SNAPSHOT_TTL_SECONDS = 7 * 24 * 3600

# Last resort when llm_models has no row for a routed model (store down on a
# cold start, model not yet allowlisted): the model-name family decides.
_PROVIDER_BY_PREFIX = (
    ("gemini-", PROVIDER_GOOGLE),
    ("gpt-", PROVIDER_OPENAI),
    ("claude-", PROVIDER_ANTHROPIC),
)


@dataclass(frozen=True)
class Route:
    model: str
    thinking_budget: int = THINKING_DEFAULT
    daily_budget_usd: float = 0.0
    provider: str = ""
    # "route" (the family's model) or "candidate" (the canary model).
    variant: str = VARIANT_ROUTE
    # The model the store asked for when it could not be served here (missing,
    # inactive, provider not drivable) and the compiled default ran instead;
    # empty otherwise. A call made with such a Route is a fallback.
    requested: str = ""


@dataclass(frozen=True)
class _Candidate:
    model: str
    thinking_budget: int
    share: int


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


def _decode_candidates(body: Any) -> dict[str, _Candidate]:
    if isinstance(body, dict) and isinstance(body.get("data"), dict):
        body = body["data"]
    out: dict[str, _Candidate] = {}
    for row in (body or {}).get("items") or []:
        family = row.get("family")
        model = (row.get("candidate_model") or "").strip()
        try:
            share = int(row.get("candidate_share") or 0)
            thinking = row.get("candidate_thinking_budget")
            thinking = THINKING_DEFAULT if thinking is None else int(thinking)
        except (TypeError, ValueError):
            continue
        if not family or not model or share <= 0:
            continue
        out[family] = _Candidate(model, thinking, min(share, 100))
    return out


def _in_share(family: str, key: Any, share: int) -> bool:
    """Whether `key` falls in the candidate's share. A key is stable: the same
    (family, key) always answers the same. With no key, each call draws."""
    if share <= 0:
        return False
    if key is None or key == "":
        return random.randrange(100) < share
    return zlib.crc32(f"{family}:{key}".encode()) % 100 < share


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
        self._candidates: dict[str, _Candidate] = {}
        self._variants: dict[tuple[str, str], str] = {}
        self._refused: dict[str, str] = {}
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
        self._logged_candidates: dict[str, tuple[str, int, int]] = {}

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
        (no store, unknown family, model missing/inactive, provider not allowed).
        Always the family's own model: the canary candidate is chosen by resolve."""
        return self._lookup(family)[0]

    def _lookup(self, family: str) -> tuple[Route | None, str]:
        """(servable stored route or None, the model the store asked for when it
        was refused, else "")."""
        if not self._base_url:
            return None, ""
        self._maybe_refresh()
        found = self._routes.get(family)
        if found is None:
            self._refused.pop(family, None)
            return None, ""
        served = self._servable(family, found)
        if served is None:
            self._refused[family] = found.model
            return None, found.model
        self._refused.pop(family, None)
        if self._logged.get(family) != served:
            self._logged[family] = served
            logger.info(
                "LLM_ROUTE resolved family=%s model=%s provider=%s thinking_budget=%d daily_budget_usd=%.4f",
                family,
                served.model,
                served.provider,
                served.thinking_budget,
                served.daily_budget_usd,
            )
        return served, ""

    def _candidate(self, family: str) -> tuple[Route, int] | None:
        """The servable canary candidate and its share, None when the family has
        none, it is the family's own model, or this process cannot serve it."""
        cand = self._candidates.get(family)
        if cand is None:
            return None
        row = self._routes.get(family)
        if row is not None and row.model == cand.model:
            return None
        budget = row.daily_budget_usd if row is not None else 0.0
        served = self._servable(
            family,
            Route(cand.model, cand.thinking_budget, budget, variant=VARIANT_CANDIDATE),
        )
        if served is None:
            return None
        sig = (cand.model, cand.thinking_budget, cand.share)
        if self._logged_candidates.get(family) != sig:
            self._logged_candidates[family] = sig
            logger.info(
                "LLM_ROUTE candidate family=%s model=%s provider=%s thinking_budget=%d share=%d",
                family,
                served.model,
                served.provider,
                served.thinking_budget,
                cand.share,
            )
        return served, cand.share

    def variant_of(self, family: str, model: str) -> str:
        """Which variant served `model` for `family` the last time it was resolved."""
        return self._variants.get((family, model), VARIANT_ROUTE)

    def fell_back(self, family: str, model: str) -> bool:
        """True when the store's route for `family` was refused here and `model`
        is not it: the compiled default ran in its place."""
        requested = self._refused.get(family)
        if not requested or requested == model:
            return False
        # A canary candidate that ran beside a refused route is not a fallback.
        return self._variants.get((family, model)) != VARIANT_CANDIDATE

    def provider_of(self, model: str) -> str:
        """The provider of `model` from the tables already loaded (never fetches)."""
        info = self._models.get(model)
        return info.provider if info is not None else infer_provider(model)

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
        if not can_drive(family, provider):
            self._warn_once(
                "provider",
                family,
                route.model,
                message="LLM_ROUTE family=%s cannot drive provider=%s here; route model=%s refused, using the compiled default",
                args=(family, provider or "unknown", route.model),
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
        key: str | None = None,
    ) -> Route:
        """The family's route, or the canary candidate for `share` percent of keys
        (stable per `key`; without a key each call draws), or the caller's default."""
        found = self.route(family)
        requested = "" if found is not None else self._refused.get(family, "")
        picked = self._candidate(family)
        if picked is not None and _in_share(family, key, picked[1]):
            route = picked[0]
            self._variants[(family, route.model)] = VARIANT_CANDIDATE
            return route
        if found is not None:
            self._variants[(family, found.model)] = VARIANT_ROUTE
            return found
        self._variants[(family, default_model)] = VARIANT_ROUTE
        return Route(
            default_model,
            default_thinking,
            0.0,
            default_provider or infer_provider(default_model),
            requested=requested,
        )

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

    def report_capabilities(self, body: dict[str, Any]) -> bool:
        """Tell localization which providers this service can drive. Never raises."""
        if not self._base_url:
            return False
        try:
            headers = {"X-Internal-API-Key": self._api_key} if self._api_key else {}
            resp = httpx.post(
                self._base_url + _CAPABILITIES_PATH,
                json=body,
                headers=headers,
                timeout=_FETCH_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            return True
        except (httpx.HTTPError, ValueError):
            return False

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
            routes, candidates = _decode(routes_body), _decode_candidates(routes_body)
            self._routes, self._candidates, self._loaded = routes, candidates, True
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
            routes = _decode(snap.get("routes"))
            candidates = _decode_candidates(snap.get("routes"))
            self._routes, self._candidates, self._loaded = routes, candidates, True
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
        "accepted",
        "rejected",
        "fallbacks",
        "lat",
        "seen",
    )

    def __init__(self) -> None:
        self.calls = self.inp = self.out = self.thinking = 0
        self.errors = self.retries = self.seen = 0
        self.accepted = self.rejected = self.fallbacks = 0
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
        outcome: str = OUTCOME_OK,
        fallback: bool = False,
    ) -> None:
        if not self.enabled or not family:
            return
        failed = bool(error) or outcome in _ERROR_OUTCOMES
        hour = int(self._clock() // 3600) * 3600
        with self._lock:
            agg = self._aggs.setdefault((hour, self._service, family, model), _Agg())
            agg.calls += 1
            agg.inp += int(input_tokens)
            agg.out += int(output_tokens)
            agg.thinking += int(thinking_tokens)
            agg.usd += float(usd)
            agg.errors += 1 if failed else 0
            agg.fallbacks += 1 if fallback else 0
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

    def record_outcome(
        self, family: str, model: str, accepted: bool, n: int = 1
    ) -> None:
        """Count `n` outputs of `model` for `family` that a check accepted or rejected."""
        n = int(n)
        if not self.enabled or not family or not model or n <= 0:
            return
        hour = int(self._clock() // 3600) * 3600
        with self._lock:
            agg = self._aggs.setdefault((hour, self._service, family, model), _Agg())
            if accepted:
                agg.accepted += n
            else:
                agg.rejected += n
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
                    "accepted": a.accepted,
                    "rejected": a.rejected,
                    "fallbacks": a.fallbacks,
                    # An outcome-only row has no call to time; None leaves the stored percentiles alone.
                    "latency_ms_p50": _percentile(a.lat, 0.50) if a.lat else None,
                    "latency_ms_p95": _percentile(a.lat, 0.95) if a.lat else None,
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
                agg.accepted += r.get("accepted", 0)
                agg.rejected += r.get("rejected", 0)
                agg.fallbacks += r.get("fallbacks", 0)

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
    """configure() from the environment, then report what this service can drive
    (once, from a background thread: fire and forget)."""
    key = (
        os.environ.get("KIELO_INTERNAL_API_KEY")
        or os.environ.get("INTERNAL_API_KEY")
        or ""
    )
    configure(service, os.environ.get("LOCALIZATION_SERVICE_URL", ""), key)
    _queue_capability_report()


def capabilities_payload() -> dict[str, Any]:
    """The body of POST llm-capabilities: google always, plus every provider this
    process declared (families None = every family)."""
    providers: list[dict[str, Any]] = [{"provider": PROVIDER_GOOGLE, "families": None}]
    for provider in sorted(_DRIVABLE):
        families = _DRIVABLE[provider]
        if provider == PROVIDER_GOOGLE or (families is not None and not families):
            continue
        providers.append(
            {
                "provider": provider,
                "families": None if families is None else sorted(families),
            }
        )
    return {"service": _service, "providers": providers}


_capability_lock = threading.Lock()
_capability_pending = False
_capability_running = False


def _post_capabilities() -> bool:
    client = _client
    if client is None or not _service:
        return False
    return client.report_capabilities(capabilities_payload())


def _capability_loop() -> None:
    global _capability_pending, _capability_running
    while True:
        # Let the start-up declarations (allow_providers after configure) land first.
        time.sleep(_CAPABILITY_DELAY_SECONDS)
        with _capability_lock:
            if not _capability_pending:
                _capability_running = False
                return
            _capability_pending = False
        try:
            _post_capabilities()
        except Exception as exc:  # never let the reporter die
            logger.warning("LLM_CAPABILITIES report failed: %s", exc)


def _queue_capability_report() -> None:
    """Ask for a capability report; calls close together share one post."""
    global _capability_pending, _capability_running
    client = _client
    if client is None or not client._base_url or not _service:
        return
    with _capability_lock:
        _capability_pending = True
        if _capability_running:
            return
        _capability_running = True
    try:
        threading.Thread(
            target=_capability_loop, daemon=True, name="llm-capabilities"
        ).start()
    except RuntimeError as exc:  # no thread to spare: the report is best effort
        with _capability_lock:
            _capability_running = False
        logger.warning("LLM_CAPABILITIES report not started: %s", exc)


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
    key: str | None = None,
) -> Route:
    """The family's model, provider and budgets; the default fills a gap (no store, unknown family).

    While the family runs a canary, ``share`` percent of keys get the candidate
    (``Route.variant == "candidate"``): pass a stable key (a deck, learner or item
    id) so one unit always sees one model; with no key each call draws."""
    if _client is None:
        return Route(
            default_model,
            default_thinking,
            0.0,
            default_provider or infer_provider(default_model),
        )
    return _client.resolve(
        family, default_model, default_thinking, default_provider, key
    )


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


def _normalize_outcome(outcome: Any, error: bool) -> str:
    name = outcome.strip().lower() if isinstance(outcome, str) else OUTCOME_OK
    if name not in OUTCOMES:
        name = OUTCOME_OK
    if error and name == OUTCOME_OK:
        return OUTCOME_ERROR
    return name


def _log_value(value: Any) -> str:
    text = str(value if value is not None else "").strip()
    return "_".join(text.split()) or "-"


def record_call(
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
    outcome: str = OUTCOME_OK,
    fallback: bool | None = None,
    variant: str | None = None,
    **_ignored: Any,
) -> None:
    """Add one finished call to the process-wide rollup and log its LLM_CALL line.
    Never raises.

    ``outcome`` is ok, error, refused or invalid_output (``error=True`` on an
    otherwise ok call means error). ``fallback`` marks a call that ran the compiled
    default because the route's model was refused; it counts under the model that
    ran. Left as None, fallback and ``variant`` come from the last resolve of the
    family in this process."""
    client = _client
    outcome = _normalize_outcome(outcome, bool(error))
    try:
        if fallback is None:
            fallback = client.fell_back(family, model) if client is not None else False
        if variant is None:
            variant = (
                client.variant_of(family, model)
                if client is not None
                else VARIANT_ROUTE
            )
        provider = (
            client.provider_of(model) if client is not None else infer_provider(model)
        )
        logger.info(
            "LLM_CALL service=%s family=%s model=%s provider=%s variant=%s in=%d out=%d thinking=%d usd=%.6f latency_ms=%d outcome=%s fallback=%d",
            _log_value(_service),
            _log_value(family),
            _log_value(model),
            _log_value(provider),
            _log_value(variant),
            int(input_tokens),
            int(output_tokens),
            int(thinking_tokens),
            float(usd),
            int(latency_ms),
            outcome,
            1 if fallback else 0,
        )
    except Exception as exc:
        logger.debug("LLM_CALL log skipped: %s", exc)
    if _recorder is None:
        return
    try:
        _recorder.record(
            family,
            model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            thinking_tokens=thinking_tokens,
            usd=usd,
            latency_ms=latency_ms,
            error=error,
            retries=retries,
            outcome=outcome,
            fallback=bool(fallback),
        )
    except Exception as exc:
        logger.debug("LLM_USAGE record skipped: %s", exc)


def record_outcome(family: str, model: str, accepted: bool, n: int = 1) -> None:
    """Count `n` outputs of `model` for `family` that the caller's own check
    accepted or rejected (a scene draft that passed its gates, a publish decision).
    Flushed with usage. Never raises."""
    if _recorder is None:
        return
    try:
        _recorder.record_outcome(family, model, accepted, n)
    except Exception as exc:
        logger.debug("LLM_USAGE outcome skipped: %s", exc)
