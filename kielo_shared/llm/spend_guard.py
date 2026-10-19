"""Paid-LLM spend guard shared by every Python service.

Refuses paid provider calls outside production unless explicitly allowed, and
caps spend with a rolling 24h USD budget and an hourly call cap counted in
Redis. Refusals raise a typed `PaidLLMCallRefused` and log one loud line.

Env (read at call time):
  ENVIRONMENT (or ENV)      production|prod => prod; anything else => non-prod.
                            Unset on Cloud Run (K_SERVICE set) counts as prod.
  LLM_ALLOW_PAID_CALLS      non-prod only: must be "true" to call a paid model.
  LLM_DAILY_BUDGET_USD      rolling 24h cap. Default 2.00 non-prod, 0 (off) prod.
  LLM_HOURLY_CALL_CAP       calls per clock hour. Default 200 non-prod, 0 (off) prod.
  LLM_GUARD_EST_USD_PER_CALL  cost booked at admission (default 0.002) and
                            corrected by `record_actual_usd` when known.
  REDIS_URL | REDIS_HOST[:port] | REDIS_HOST + REDIS_PORT, REDIS_PASSWORD
                            counter store. REDIS_HOST may be "host:port" (the
                            convo VM passes it that way) or a redis:// URL.

Non-prod fails closed when Redis is unreachable; prod fails open (logged).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# The control-plane task family of the call in flight (kielo_shared.llmroute);
# set by the caller around a model call so the guard can book it per family.
llm_family_var: ContextVar[str] = ContextVar("llm_family", default="")

_PROD_NAMES = {"production", "prod"}
_KEY_PREFIX = "kielo:llmguard"
_MICRO = 1_000_000
_BUCKET_SECONDS = 3600
_WINDOW_BUCKETS = 24
_DEFAULT_NONPROD_BUDGET_USD = 2.00
_DEFAULT_NONPROD_HOURLY_CAP = 200
_DEFAULT_EST_USD_PER_CALL = 0.002


class PaidLLMCallRefused(RuntimeError):
    """A paid model call was refused by the guard. Deterministic: never retry."""

    def __init__(self, message: str, *, reason: str, task: str = "") -> None:
        super().__init__(message)
        self.reason = reason
        self.task = task


class PaidLLMCallsDisabled(PaidLLMCallRefused):
    """Non-production and LLM_ALLOW_PAID_CALLS is not true."""


class LLMBudgetExceeded(PaidLLMCallRefused):
    """Rolling daily USD budget or hourly call cap reached."""


class LLMGuardUnavailable(PaidLLMCallRefused):
    """Counter store unreachable in non-production (fail closed)."""


def is_production(env: dict[str, str] | None = None) -> bool:
    e = env if env is not None else os.environ
    # ENV is the older spelling: the convo VM set only ENV=production and
    # every paid call there was refused as non-prod (2026-10-03).
    name = (e.get("ENVIRONMENT") or e.get("ENV") or "").strip().lower()
    if name:
        return name in _PROD_NAMES
    return bool(e.get("K_SERVICE"))


def _float(e: Mapping[str, str], key: str, default: float) -> float:
    raw = (e.get(key) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _int(e: Mapping[str, str], key: str, default: int) -> int:
    return int(_float(e, key, float(default)))


# The guard sits on audio paths: keep every Redis round trip short, fail open in
# production, and never wait on the store from an asyncio loop for longer than
# _LOOP_WAIT_SECONDS.
_REDIS_TIMEOUT_SECONDS = 0.2
_LOOP_WAIT_SECONDS = 0.25


def _split_host_port(raw: str) -> tuple[str, int | None]:
    host, sep, port = raw.rpartition(":")
    if sep and host and port.isdigit() and ":" not in host:
        return host, int(port)
    return raw, None


@dataclass(frozen=True)
class RedisTarget:
    """Where the counters live: a URL, or host/port/password."""

    url: str = ""
    host: str = ""
    port: int = 6379
    password: str | None = None


def redis_target(env: Mapping[str, str] | None = None) -> RedisTarget:
    """Resolve REDIS_URL | REDIS_HOST[:port] | REDIS_HOST + REDIS_PORT.

    Pure (no redis import): REDIS_HOST may carry its port ("10.0.0.3:6379", how
    the convo VM passes it) or be a redis:// URL. Raises RuntimeError when
    nothing is configured.
    """
    e = env if env is not None else os.environ
    url = (e.get("REDIS_URL") or "").strip()
    host = (e.get("REDIS_HOST") or "").strip()
    if not url and host.startswith(("redis://", "rediss://", "unix://")):
        url = host
    if url:
        return RedisTarget(url=url)
    if not host:
        raise RuntimeError("no REDIS_URL/REDIS_HOST configured")
    host, port = _split_host_port(host)
    return RedisTarget(
        host=host,
        port=port if port is not None else _int(e, "REDIS_PORT", 6379),
        password=(e.get("REDIS_PASSWORD") or None),
    )


def _default_redis_factory() -> Any:
    import redis  # type: ignore[import-not-found]
    from redis.backoff import NoBackoff  # type: ignore[import-not-found]
    from redis.retry import Retry  # type: ignore[import-not-found]

    target = redis_target()
    kwargs: dict[str, Any] = {
        "socket_connect_timeout": _REDIS_TIMEOUT_SECONDS,
        "socket_timeout": _REDIS_TIMEOUT_SECONDS,
        "decode_responses": True,
        # redis-py retries timeouts with backoff by default (seconds per call):
        # the guard fails fast and open instead.
        "retry": Retry(NoBackoff(), 0),
    }
    if target.url:
        return redis.Redis.from_url(target.url, **kwargs)
    return redis.Redis(
        host=target.host, port=target.port, password=target.password, **kwargs
    )


_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="llm-guard")


def _loop_running() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


_redis_factory: Callable[[], Any] = _default_redis_factory
_redis_client: Any = None
_clock: Callable[[], float] = time.time


def set_redis_factory(factory: Callable[[], Any] | None) -> None:
    """Test hook / explicit wiring. Resets the cached client."""
    global _redis_factory, _redis_client, _admit_script, _admit_script_client
    _redis_factory = factory or _default_redis_factory
    _redis_client = None
    _admit_script = None
    _admit_script_client = None


def set_clock(clock: Callable[[], float] | None) -> None:
    global _clock
    _clock = clock or time.time


def _client() -> Any:
    global _redis_client
    if _redis_client is None:
        _redis_client = _redis_factory()
    return _redis_client


def _refuse(exc: PaidLLMCallRefused) -> PaidLLMCallRefused:
    logger.error(
        "LLM_GUARD_REFUSED reason=%s task=%s detail=%s",
        exc.reason,
        exc.task or "-",
        exc,
    )
    return exc


def _bucket(now: float) -> int:
    return int(now // _BUCKET_SECONDS)


def _usd_key(bucket: int) -> str:
    return f"{_KEY_PREFIX}:usd:{bucket}"


def _calls_key(bucket: int) -> str:
    return f"{_KEY_PREFIX}:calls:{bucket}"


def paid_calls_enabled() -> bool:
    """False outside production unless LLM_ALLOW_PAID_CALLS=true.

    For background loops and schedulers to skip quietly instead of raising.
    """
    if is_production():
        return True
    return (os.environ.get("LLM_ALLOW_PAID_CALLS") or "").strip().lower() == "true"


def _family_usd_key(family: str, bucket: int) -> str:
    return f"{_KEY_PREFIX}:fam:{family}:usd:{bucket}"


def _family_budget(family: str) -> float:
    if not family:
        return 0.0
    try:
        from kielo_shared import llmroute

        return llmroute.daily_budget_usd(family)
    except Exception:
        return 0.0


def _admit_family(family: str, task: str, est_micro: int, prod: bool) -> None:
    """Rolling-24h per-family cap from the control plane; books the estimate."""
    budget = _family_budget(family)
    if budget <= 0:
        return
    current = _bucket(_clock())
    try:
        r = _client()
        keys = [_family_usd_key(family, current - i) for i in range(_WINDOW_BUCKETS)]
        spent_micro = sum(int(v or 0) for v in r.mget(keys))
        if spent_micro >= int(budget * _MICRO):
            raise _refuse(
                LLMBudgetExceeded(
                    f"family {family} daily budget reached (${spent_micro / _MICRO:.2f} of ${budget:.2f})",
                    reason="family_daily_budget",
                    task=task,
                )
            )
        key = _family_usd_key(family, current)
        r.incrby(key, est_micro)
        r.expire(key, _BUCKET_SECONDS * (_WINDOW_BUCKETS + 1))
    except PaidLLMCallRefused:
        raise
    except Exception as exc:
        if prod:
            logger.error(
                "LLM_GUARD_UNAVAILABLE family budget failing open in production: %s",
                exc,
            )
            return
        raise _refuse(
            LLMGuardUnavailable(
                f"LLM spend counter unreachable ({type(exc).__name__}); refusing paid call",
                reason="guard_unavailable",
                task=task,
            )
        ) from exc


_ADMIT_SCRIPT_SRC = """
local nfam = tonumber(ARGV[1])
local est = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
if nfam > 0 then
  local spent = 0
  for i = 1, nfam do
    spent = spent + (tonumber(redis.call('GET', KEYS[i])) or 0)
  end
  if spent >= tonumber(ARGV[4]) then return {1, spent} end
  redis.call('INCRBY', KEYS[1], est)
  redis.call('EXPIRE', KEYS[1], ttl)
end
if ARGV[5] == '0' then return {0, 0} end
local calls = redis.call('INCR', KEYS[nfam + 1])
if calls == 1 then redis.call('EXPIRE', KEYS[nfam + 1], tonumber(ARGV[6])) end
local cap = tonumber(ARGV[7])
if cap > 0 and calls > cap then return {2, calls} end
if ARGV[8] == '1' then
  local spent = 0
  for i = nfam + 2, nfam + 1 + tonumber(ARGV[9]) do
    spent = spent + (tonumber(redis.call('GET', KEYS[i])) or 0)
  end
  if spent >= tonumber(ARGV[10]) then return {3, spent} end
  redis.call('INCRBY', KEYS[nfam + 2], est)
  redis.call('EXPIRE', KEYS[nfam + 2], ttl)
end
return {0, 0}
"""

_admit_script: Any = None
_admit_script_client: Any = None


def _script_unsupported() -> tuple[type[BaseException], ...]:
    try:
        from redis.exceptions import ResponseError  # type: ignore[import-not-found]
    except ImportError:
        return ()
    return (ResponseError,)


def _admit_scripted(
    family: str,
    family_budget: float,
    task: str,
    est_micro: int,
    budget: float,
    hourly_cap: int,
    prod: bool,
) -> bool:
    """The admission checks as ONE Redis round trip (same commands, same order,
    same early exits as `_admit_sequential`; the script makes them atomic too).

    Returns False when the store cannot run it, so the caller falls back.
    """
    global _admit_script, _admit_script_client
    current = _bucket(_clock())
    fam_on = family_budget > 0
    try:
        r = _client()
        if not hasattr(r, "register_script"):
            return False
        if _admit_script is None or _admit_script_client is not r:
            _admit_script = r.register_script(_ADMIT_SCRIPT_SRC)
            _admit_script_client = r
        keys: list[str] = []
        if fam_on:
            keys += [
                _family_usd_key(family, current - i) for i in range(_WINDOW_BUCKETS)
            ]
        keys.append(_calls_key(current))
        keys += [_usd_key(current - i) for i in range(_WINDOW_BUCKETS)]
        global_on = budget > 0 or hourly_cap > 0
        args = [
            _WINDOW_BUCKETS if fam_on else 0,
            est_micro,
            _BUCKET_SECONDS * (_WINDOW_BUCKETS + 1),
            int(family_budget * _MICRO) if fam_on else 0,
            1 if global_on else 0,
            _BUCKET_SECONDS * 2,
            max(hourly_cap, 0),
            1 if budget > 0 else 0,
            _WINDOW_BUCKETS,
            int(budget * _MICRO) if budget > 0 else 0,
        ]
        code, spent = (int(x) for x in _admit_script(keys=keys, args=args))
    except _script_unsupported():
        logger.warning("LLM_GUARD admission script unsupported; using sequential path")
        return False
    except Exception as exc:
        if prod:
            logger.error("LLM_GUARD_UNAVAILABLE failing open in production: %s", exc)
            return True
        raise _refuse(
            LLMGuardUnavailable(
                f"LLM spend counter unreachable ({type(exc).__name__}); refusing paid call",
                reason="guard_unavailable",
                task=task,
            )
        ) from exc
    if code == 1:
        raise _refuse(
            LLMBudgetExceeded(
                f"family {family} daily budget reached (${spent / _MICRO:.2f} of ${family_budget:.2f})",
                reason="family_daily_budget",
                task=task,
            )
        )
    if code == 2:
        raise _refuse(
            LLMBudgetExceeded(
                f"hourly LLM call cap reached ({hourly_cap}/h)",
                reason="hourly_cap",
                task=task,
            )
        )
    if code == 3:
        raise _refuse(
            LLMBudgetExceeded(
                f"rolling 24h LLM budget reached (${spent / _MICRO:.2f} of ${budget:.2f})",
                reason="daily_budget",
                task=task,
            )
        )
    return True


def admit_paid_call(
    task: str = "", *, provider: str = "", book: bool = True, family: str = ""
) -> None:
    """Gate one paid model call. Raises PaidLLMCallRefused, else books the call.

    Call immediately before the network request; every retry is a call.
    `book=False` only applies the paid-calls switch (no counters), for outer
    layers whose inner layer books each real call.
    """
    e = os.environ
    prod = is_production()
    if not prod and (e.get("LLM_ALLOW_PAID_CALLS") or "").strip().lower() != "true":
        raise _refuse(
            PaidLLMCallsDisabled(
                "paid LLM calls are disabled outside production; set LLM_ALLOW_PAID_CALLS=true to allow",
                reason="paid_calls_disabled",
                task=task,
            )
        )

    if not book:
        return

    family = family or llm_family_var.get()
    est_micro = int(
        max(0.0, _float(e, "LLM_GUARD_EST_USD_PER_CALL", _DEFAULT_EST_USD_PER_CALL))
        * _MICRO
    )
    budget = _float(
        e, "LLM_DAILY_BUDGET_USD", 0.0 if prod else _DEFAULT_NONPROD_BUDGET_USD
    )
    hourly_cap = _int(
        e, "LLM_HOURLY_CALL_CAP", 0 if prod else _DEFAULT_NONPROD_HOURLY_CAP
    )
    family_budget = _family_budget(family) if family else 0.0
    if family_budget <= 0 and budget <= 0 and hourly_cap <= 0:
        return

    if _admit_scripted(
        family, family_budget, task, est_micro, budget, hourly_cap, prod
    ):
        return
    _admit_sequential(family, task, est_micro, budget, hourly_cap, prod)


def _admit_sequential(
    family: str,
    task: str,
    est_micro: int,
    budget: float,
    hourly_cap: int,
    prod: bool,
) -> None:
    """One Redis round trip per command. Used when the store cannot run the
    admission script (a stub client, a cluster that rejects cross-slot keys)."""
    if family:
        _admit_family(family, task, est_micro, prod)
    if budget <= 0 and hourly_cap <= 0:
        return
    now = _clock()
    current = _bucket(now)
    try:
        r = _client()
        calls_key = _calls_key(current)
        calls = int(r.incr(calls_key))
        if calls == 1:
            r.expire(calls_key, _BUCKET_SECONDS * 2)
        if hourly_cap > 0 and calls > hourly_cap:
            raise _refuse(
                LLMBudgetExceeded(
                    f"hourly LLM call cap reached ({hourly_cap}/h)",
                    reason="hourly_cap",
                    task=task,
                )
            )
        if budget > 0:
            keys = [_usd_key(current - i) for i in range(_WINDOW_BUCKETS)]
            spent_micro = sum(int(v or 0) for v in r.mget(keys))
            if spent_micro >= int(budget * _MICRO):
                raise _refuse(
                    LLMBudgetExceeded(
                        f"rolling 24h LLM budget reached (${spent_micro / _MICRO:.2f} of ${budget:.2f})",
                        reason="daily_budget",
                        task=task,
                    )
                )
            usd_key = _usd_key(current)
            r.incrby(usd_key, est_micro)
            r.expire(usd_key, _BUCKET_SECONDS * (_WINDOW_BUCKETS + 1))
    except PaidLLMCallRefused:
        raise
    except Exception as exc:
        if prod:
            logger.error("LLM_GUARD_UNAVAILABLE failing open in production: %s", exc)
            return
        raise _refuse(
            LLMGuardUnavailable(
                f"LLM spend counter unreachable ({type(exc).__name__}); refusing paid call",
                reason="guard_unavailable",
                task=task,
            )
        ) from exc


def _book(bookings: list[tuple[str, int]]) -> None:
    """INCRBY + EXPIRE for each (key, delta), in one pipelined round trip."""
    if not bookings:
        return
    r = _client()
    ttl = _BUCKET_SECONDS * (_WINDOW_BUCKETS + 1)
    if not hasattr(r, "pipeline"):
        for key, delta in bookings:
            r.incrby(key, delta)
            r.expire(key, ttl)
        return
    pipe = r.pipeline(transaction=False)
    for key, delta in bookings:
        pipe.incrby(key, delta)
        pipe.expire(key, ttl)
    pipe.execute()


def record_actual_usd(actual_usd: float, *, family: str = "") -> None:
    """Replace the admission estimate with the real cost of the finished call."""
    family = family or llm_family_var.get()
    e = os.environ
    prod = is_production()
    budget = _float(
        e, "LLM_DAILY_BUDGET_USD", 0.0 if prod else _DEFAULT_NONPROD_BUDGET_USD
    )
    family_on = bool(family) and _family_budget(family) > 0
    if budget <= 0 and not family_on:
        return
    est = int(
        max(0.0, _float(e, "LLM_GUARD_EST_USD_PER_CALL", _DEFAULT_EST_USD_PER_CALL))
        * _MICRO
    )
    delta = int(max(0.0, actual_usd) * _MICRO) - est
    if delta == 0:
        return
    current = _bucket(_clock())
    bookings: list[tuple[str, int]] = []
    if family_on:
        bookings.append((_family_usd_key(family, current), delta))
    if budget > 0:
        bookings.append((_usd_key(current), delta))
    try:
        _book(bookings)
    except Exception as exc:
        logger.warning("LLM_GUARD spend adjust failed: %s", exc)


HEADROOM_OK = "ok"
HEADROOM_FAMILY_OVER = "family_daily_budget"
HEADROOM_GLOBAL_OVER = "daily_budget"
HEADROOM_DISABLED = "paid_calls_disabled"
HEADROOM_UNAVAILABLE = "guard_unavailable"


def _headroom_blocking(family: str, prod: bool) -> str:
    e = os.environ
    budget = _float(
        e, "LLM_DAILY_BUDGET_USD", 0.0 if prod else _DEFAULT_NONPROD_BUDGET_USD
    )
    family_budget = _family_budget(family) if family else 0.0
    if budget <= 0 and family_budget <= 0:
        return HEADROOM_OK
    current = _bucket(_clock())
    r = _client()
    global_keys = (
        [_usd_key(current - i) for i in range(_WINDOW_BUCKETS)] if budget > 0 else []
    )
    family_keys = (
        [_family_usd_key(family, current - i) for i in range(_WINDOW_BUCKETS)]
        if family_budget > 0
        else []
    )
    if global_keys and family_keys and hasattr(r, "pipeline"):
        pipe = r.pipeline(transaction=False)
        pipe.mget(global_keys)
        pipe.mget(family_keys)
        global_vals, family_vals = pipe.execute()
    else:
        global_vals = r.mget(global_keys) if global_keys else None
        family_vals = None
    if global_keys and sum(int(v or 0) for v in global_vals) >= int(budget * _MICRO):
        return HEADROOM_GLOBAL_OVER
    if family_keys:
        if family_vals is None:
            family_vals = r.mget(family_keys)
        if sum(int(v or 0) for v in family_vals) >= int(family_budget * _MICRO):
            return HEADROOM_FAMILY_OVER
    return HEADROOM_OK


def _headroom_failed(exc: BaseException, prod: bool) -> str:
    if prod:
        logger.error(
            "LLM_GUARD_UNAVAILABLE headroom check failing open: %s: %s",
            type(exc).__name__,
            exc,
        )
        return HEADROOM_OK
    return HEADROOM_UNAVAILABLE


def session_headroom(family: str = "") -> str:
    """Read-only: why a new paid session may or may not start (HEADROOM_*).

    For callers that cannot be refused mid-flight (a live voice call): check once
    when the session is built, then book usage with ``record_usd``. The global
    rolling-24h budget wins over the family cap (a family over its cap may still
    run on a cheaper route; the global ceiling refuses). Books nothing.
    Production fails open when the counters are unreachable.

    Prefer ``asession_headroom`` from async code. Called on a running loop this
    reads the store on a worker thread and waits at most _LOOP_WAIT_SECONDS.
    """
    if not paid_calls_enabled():
        return HEADROOM_DISABLED
    family = family or llm_family_var.get()
    prod = is_production()
    try:
        if _loop_running():
            return _executor.submit(_headroom_blocking, family, prod).result(
                timeout=_LOOP_WAIT_SECONDS
            )
        return _headroom_blocking(family, prod)
    except Exception as exc:
        return _headroom_failed(exc, prod)


async def asession_headroom(family: str = "") -> str:
    """``session_headroom`` without blocking the event loop at all."""
    if not paid_calls_enabled():
        return HEADROOM_DISABLED
    family = family or llm_family_var.get()
    prod = is_production()
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_executor, _headroom_blocking, family, prod),
            timeout=_LOOP_WAIT_SECONDS + 0.15,
        )
    except Exception as exc:
        return _headroom_failed(exc, prod)


def has_headroom(family: str = "") -> bool:
    return session_headroom(family) == HEADROOM_OK


def _record_usd_blocking(micro: int, family: str, include_global: bool = True) -> None:
    e = os.environ
    budget = _float(
        e,
        "LLM_DAILY_BUDGET_USD",
        0.0 if is_production() else _DEFAULT_NONPROD_BUDGET_USD,
    )
    current = _bucket(_clock())
    try:
        bookings: list[tuple[str, int]] = []
        if family and _family_budget(family) > 0:
            bookings.append((_family_usd_key(family, current), micro))
        if budget > 0 and include_global:
            bookings.append((_usd_key(current), micro))
        _book(bookings)
    except Exception as exc:
        logger.warning("LLM_GUARD spend booking failed: %s", exc)


def record_usd(usd: float, *, family: str = "", include_global: bool = True) -> None:
    """Book the full cost of a call that was never admitted (a session admitted
    once by ``session_headroom``). Never raises, never waits on an asyncio loop.
    ``include_global=False`` books the family only (the global counter already
    holds the call's admission estimate)."""
    micro = int(max(0.0, usd) * _MICRO)
    if micro == 0:
        return
    family = family or llm_family_var.get()
    if _loop_running():
        try:
            _executor.submit(_record_usd_blocking, micro, family, include_global)
        except RuntimeError as exc:
            # The executor refuses work once the interpreter is shutting down.
            logger.warning("LLM_GUARD spend booking dropped (shutting down): %s", exc)
        return
    _record_usd_blocking(micro, family, include_global)


__all__ = [
    "LLMBudgetExceeded",
    "LLMGuardUnavailable",
    "PaidLLMCallRefused",
    "PaidLLMCallsDisabled",
    "admit_paid_call",
    "HEADROOM_DISABLED",
    "HEADROOM_FAMILY_OVER",
    "HEADROOM_GLOBAL_OVER",
    "HEADROOM_OK",
    "HEADROOM_UNAVAILABLE",
    "asession_headroom",
    "has_headroom",
    "is_production",
    "llm_family_var",
    "paid_calls_enabled",
    "record_actual_usd",
    "record_usd",
    "set_clock",
    "session_headroom",
    "set_redis_factory",
]
