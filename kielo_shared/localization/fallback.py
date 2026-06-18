"""FallbackDecorator + CircuitBreaker — Phase C7.

Stack a primary provider with one or more secondaries. On batch failure
(exception or empty/malformed result list) the decorator advances to the
next provider. A simple per-provider circuit breaker keeps a flapping
backend from soaking every request with retries.

Usage:

    primary = OpenAIProvider(...)
    secondary = GeminiProvider(...)
    chain = FallbackDecorator([primary, secondary])
    registry.register("translate-resilient", chain)
"""

from __future__ import annotations

import logging
import time
from typing import Iterable

from kielo_shared.localization.provider import LocalizationProvider
from kielo_shared.localization.types import TranslationItem, TranslationResult


logger = logging.getLogger(__name__)


# ──────────────────────── CircuitBreaker (minimal) ───────────────────────


class CircuitBreaker:
    """Tiny sliding-window failure tracker.

    States: CLOSED (allow), OPEN (block, until recovery_secs elapsed),
    HALF_OPEN (one trial allowed; success → CLOSED, failure → OPEN again).

    Phase C7 goal is "stop hammering a flapping provider"; sophistication
    (token bucket / response-code filtering) deferred.
    """

    _STATE_CLOSED = "closed"
    _STATE_OPEN = "open"
    _STATE_HALF_OPEN = "half_open"

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        recovery_secs: float = 30.0,
    ) -> None:
        self._threshold = max(1, failure_threshold)
        self._recovery_secs = max(0.1, recovery_secs)
        self._failures = 0
        self._opened_at = 0.0
        self._state = self._STATE_CLOSED

    def allow(self) -> bool:
        if self._state == self._STATE_CLOSED:
            return True
        elapsed = time.monotonic() - self._opened_at
        if self._state == self._STATE_OPEN and elapsed >= self._recovery_secs:
            self._state = self._STATE_HALF_OPEN
            return True
        return self._state == self._STATE_HALF_OPEN

    def record_success(self) -> None:
        self._failures = 0
        self._state = self._STATE_CLOSED

    def record_failure(self) -> None:
        self._failures += 1
        if self._state == self._STATE_HALF_OPEN:
            # Trial blew up — re-open and reset the timer.
            self._opened_at = time.monotonic()
            self._state = self._STATE_OPEN
            return
        if self._failures >= self._threshold:
            self._opened_at = time.monotonic()
            self._state = self._STATE_OPEN

    @property
    def state(self) -> str:
        return self._state


# ───────────────────────────── FallbackDecorator ─────────────────────────


class FallbackDecorator:
    """Sequential fallback chain with per-provider circuit breakers.

    For each call:
      1. Walk providers in order.
      2. Skip any whose breaker is OPEN.
      3. Try translate_batch. On exception OR empty result, record failure
         and advance.
      4. Return the first successful result. If all providers fail, re-raise
         the last exception.

    The decorator's `provider_id` is the stable chain id (caller-supplied) —
    individual results carry their actual producing provider via
    `TranslationResult.provider` for telemetry.
    """

    def __init__(
        self,
        providers: Iterable[LocalizationProvider],
        *,
        chain_id: str = "fallback-chain",
        breaker_threshold: int = 5,
        breaker_recovery_secs: float = 30.0,
    ) -> None:
        self._providers: list[LocalizationProvider] = list(providers)
        if not self._providers:
            raise ValueError("FallbackDecorator requires at least one provider")
        self._chain_id = chain_id
        self._breakers: list[CircuitBreaker] = [
            CircuitBreaker(
                failure_threshold=breaker_threshold,
                recovery_secs=breaker_recovery_secs,
            )
            for _ in self._providers
        ]

    @property
    def provider_id(self) -> str:
        return self._chain_id

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
        idempotency_key: str | None = None,
    ) -> list[TranslationResult]:
        last_error: Exception | None = None
        for idx, provider in enumerate(self._providers):
            breaker = self._breakers[idx]
            if not breaker.allow():
                logger.debug(
                    "FallbackDecorator: skip %s — breaker %s",
                    provider.provider_id,
                    breaker.state,
                )
                continue
            try:
                results = await provider.translate_batch(
                    items,
                    source_locale=source_locale,
                    target_locale=target_locale,
                    idempotency_key=idempotency_key,
                )
            except Exception as exc:
                breaker.record_failure()
                last_error = exc
                logger.warning(
                    "FallbackDecorator: %s raised %s — advancing.",
                    provider.provider_id,
                    type(exc).__name__,
                )
                continue
            if not results or len(results) != len(items):
                breaker.record_failure()
                logger.warning(
                    "FallbackDecorator: %s returned %d for %d items — advancing.",
                    provider.provider_id,
                    len(results) if results else 0,
                    len(items),
                )
                continue
            breaker.record_success()
            return results
        if last_error is not None:
            raise last_error
        # All breakers open + no exception captured — degrade to passthrough
        # so the caller doesn't get a None response.
        logger.warning("FallbackDecorator: all providers unavailable; passthrough.")
        return [
            TranslationResult(text=item.text, provider="passthrough") for item in items
        ]


__all__ = ["CircuitBreaker", "FallbackDecorator"]
