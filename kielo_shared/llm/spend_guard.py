"""Paid-LLM spend guard shared by every Python service.

Refuses paid provider calls outside production unless explicitly allowed, and
caps spend with a rolling 24h USD budget and an hourly call cap counted in
Redis. Refusals raise a typed `PaidLLMCallRefused` and log one loud line.

Env (read at call time):
  ENVIRONMENT               production|prod => prod; anything else => non-prod.
                            Unset on Cloud Run (K_SERVICE set) counts as prod.
  LLM_ALLOW_PAID_CALLS      non-prod only: must be "true" to call a paid model.
  LLM_DAILY_BUDGET_USD      rolling 24h cap. Default 2.00 non-prod, 0 (off) prod.
  LLM_HOURLY_CALL_CAP       calls per clock hour. Default 200 non-prod, 0 (off) prod.
  LLM_GUARD_EST_USD_PER_CALL  cost booked at admission (default 0.002) and
                            corrected by `record_actual_usd` when known.
  REDIS_URL | REDIS_HOST/REDIS_PORT/REDIS_PASSWORD   counter store.

Non-prod fails closed when Redis is unreachable; prod fails open (logged).
"""

from __future__ import annotations

import logging
import os
import time
from contextvars import ContextVar
from typing import Any, Callable

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
    name = (e.get("ENVIRONMENT") or "").strip().lower()
    if name:
        return name in _PROD_NAMES
    return bool(e.get("K_SERVICE"))


def _float(e: dict[str, str] | os._Environ, key: str, default: float) -> float:
    raw = (e.get(key) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _int(e: dict[str, str] | os._Environ, key: str, default: int) -> int:
    return int(_float(e, key, float(default)))


def _default_redis_factory() -> Any:
    import redis  # type: ignore[import-not-found]

    e = os.environ
    kwargs: dict[str, Any] = {
        "socket_connect_timeout": 1.0,
        "socket_timeout": 1.0,
        "decode_responses": True,
    }
    url = (e.get("REDIS_URL") or "").strip()
    if url:
        return redis.Redis.from_url(url, **kwargs)
    host = (e.get("REDIS_HOST") or "").strip()
    if not host:
        raise RuntimeError("no REDIS_URL/REDIS_HOST configured")
    return redis.Redis(
        host=host,
        port=_int(e, "REDIS_PORT", 6379),
        password=(e.get("REDIS_PASSWORD") or None),
        **kwargs,
    )


_redis_factory: Callable[[], Any] = _default_redis_factory
_redis_client: Any = None
_clock: Callable[[], float] = time.time


def set_redis_factory(factory: Callable[[], Any] | None) -> None:
    """Test hook / explicit wiring. Resets the cached client."""
    global _redis_factory, _redis_client
    _redis_factory = factory or _default_redis_factory
    _redis_client = None


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
    if family:
        _admit_family(
            family,
            task,
            int(
                max(
                    0.0,
                    _float(e, "LLM_GUARD_EST_USD_PER_CALL", _DEFAULT_EST_USD_PER_CALL),
                )
                * _MICRO
            ),
            prod,
        )

    budget = _float(
        e, "LLM_DAILY_BUDGET_USD", 0.0 if prod else _DEFAULT_NONPROD_BUDGET_USD
    )
    hourly_cap = _int(
        e, "LLM_HOURLY_CALL_CAP", 0 if prod else _DEFAULT_NONPROD_HOURLY_CAP
    )
    if budget <= 0 and hourly_cap <= 0:
        return

    est_micro = int(
        max(0.0, _float(e, "LLM_GUARD_EST_USD_PER_CALL", _DEFAULT_EST_USD_PER_CALL))
        * _MICRO
    )
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


def _record_family_usd(family: str, actual_usd: float) -> None:
    if _family_budget(family) <= 0:
        return
    est = int(
        max(
            0.0,
            _float(os.environ, "LLM_GUARD_EST_USD_PER_CALL", _DEFAULT_EST_USD_PER_CALL),
        )
        * _MICRO
    )
    delta = int(max(0.0, actual_usd) * _MICRO) - est
    if delta == 0:
        return
    try:
        r = _client()
        key = _family_usd_key(family, _bucket(_clock()))
        r.incrby(key, delta)
        r.expire(key, _BUCKET_SECONDS * (_WINDOW_BUCKETS + 1))
    except Exception as exc:
        logger.warning("LLM_GUARD family spend adjust failed: %s", exc)


def record_actual_usd(actual_usd: float, *, family: str = "") -> None:
    """Replace the admission estimate with the real cost of the finished call."""
    family = family or llm_family_var.get()
    if family:
        _record_family_usd(family, actual_usd)
    e = os.environ
    prod = is_production()
    budget = _float(
        e, "LLM_DAILY_BUDGET_USD", 0.0 if prod else _DEFAULT_NONPROD_BUDGET_USD
    )
    if budget <= 0:
        return
    est = int(
        max(0.0, _float(e, "LLM_GUARD_EST_USD_PER_CALL", _DEFAULT_EST_USD_PER_CALL))
        * _MICRO
    )
    delta = int(max(0.0, actual_usd) * _MICRO) - est
    if delta == 0:
        return
    try:
        r = _client()
        key = _usd_key(_bucket(_clock()))
        r.incrby(key, delta)
        r.expire(key, _BUCKET_SECONDS * (_WINDOW_BUCKETS + 1))
    except Exception as exc:
        logger.warning("LLM_GUARD spend adjust failed: %s", exc)


__all__ = [
    "LLMBudgetExceeded",
    "LLMGuardUnavailable",
    "PaidLLMCallRefused",
    "PaidLLMCallsDisabled",
    "admit_paid_call",
    "is_production",
    "llm_family_var",
    "paid_calls_enabled",
    "record_actual_usd",
    "set_clock",
    "set_redis_factory",
]
