"""Composable decorators that wrap a `LocalizationProvider`.

Phase B keeps the set tight:
  - `MetricsDecorator`: structured-log per-batch (provider, target, role
    distribution, item count, total latency, char count). Emits to stdlib
    `logging`; metrics surface (Prometheus, OTLP) plugs in later by
    swapping the `emit` callback.
  - `CorrelationDecorator`: stamp results with a trace id from a contextvar
    if callers haven't supplied one. Lets logs in any service correlate
    a translation back to its triggering request.

Decorators are themselves `LocalizationProvider`s so they can be stacked:

    >>> provider = MetricsDecorator(CorrelationDecorator(OpenAIProvider(...)))
"""

from __future__ import annotations

import logging
import time
import uuid
from contextvars import ContextVar
from typing import Callable

from kielo_shared.localization.provider import LocalizationProvider
from kielo_shared.localization.types import TranslationItem, TranslationResult


logger = logging.getLogger(__name__)


# Caller can set this contextvar to thread a trace id through. Most engine
# call sites already use a request-scoped trace id from FastAPI middleware;
# the CorrelationDecorator picks it up here.
localization_trace_var: ContextVar[str] = ContextVar(
    "localization_trace_id", default=""
)


# ─────────────────────────── MetricsDecorator ────────────────────────────


MetricsEmit = Callable[[dict], None]


def _default_emit(record: dict) -> None:
    """Default metrics sink: structured log line.

    Switching to Prometheus / OTLP later is a one-call swap at construction
    site (pass `emit=...` to MetricsDecorator) — interface stays stable.
    """
    logger.info("localization_batch %s", record)


class MetricsDecorator:
    """Emit one structured record per batch call.

    Record shape:
      provider, source_locale, target_locale, item_count, char_count,
      latency_ms, role_counts, error.
    """

    def __init__(
        self,
        inner: LocalizationProvider,
        *,
        emit: MetricsEmit | None = None,
    ) -> None:
        self._inner = inner
        self._emit = emit or _default_emit

    @property
    def provider_id(self) -> str:
        return self._inner.provider_id

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
        idempotency_key: str | None = None,
    ) -> list[TranslationResult]:
        start = time.perf_counter()
        char_count = sum(len(item.text or "") for item in items)
        role_counts: dict[str, int] = {}
        for item in items:
            role_counts[item.role] = role_counts.get(item.role, 0) + 1
        error: str | None = None
        try:
            results = await self._inner.translate_batch(
                items,
                source_locale=source_locale,
                target_locale=target_locale,
                idempotency_key=idempotency_key,
            )
            return results
        except Exception as exc:
            error = type(exc).__name__
            raise
        finally:
            self._emit(
                {
                    "provider": self.provider_id,
                    "source_locale": source_locale,
                    "target_locale": target_locale,
                    "item_count": len(items),
                    "char_count": char_count,
                    "role_counts": role_counts,
                    "latency_ms": int((time.perf_counter() - start) * 1000),
                    "error": error,
                }
            )


# ──────────────────────── CorrelationDecorator ───────────────────────────


class CorrelationDecorator:
    """Stamp a correlation id onto every result.

    Picks the id in this order:
      1. `idempotency_key` passed to translate_batch (caller-supplied)
      2. `localization_trace_var` contextvar (request-scoped middleware)
      3. fresh uuid4() — every batch gets one so logs line up

    Inner provider may already populate `correlation_id`; we only fill
    when empty so providers that have a richer trace stay unmodified.
    """

    def __init__(self, inner: LocalizationProvider) -> None:
        self._inner = inner

    @property
    def provider_id(self) -> str:
        return self._inner.provider_id

    async def translate_batch(
        self,
        items: list[TranslationItem],
        *,
        source_locale: str,
        target_locale: str,
        idempotency_key: str | None = None,
    ) -> list[TranslationResult]:
        trace_id = (
            (idempotency_key or "").strip()
            or (localization_trace_var.get() or "").strip()
            or uuid.uuid4().hex
        )
        results = await self._inner.translate_batch(
            items,
            source_locale=source_locale,
            target_locale=target_locale,
            idempotency_key=idempotency_key,
        )
        stamped: list[TranslationResult] = []
        for result in results:
            if result.correlation_id:
                stamped.append(result)
                continue
            stamped.append(
                TranslationResult(
                    text=result.text,
                    provider=result.provider,
                    cached=result.cached,
                    latency_ms=result.latency_ms,
                    confidence=result.confidence,
                    correlation_id=trace_id,
                    metadata=result.metadata,
                )
            )
        return stamped


__all__ = [
    "CorrelationDecorator",
    "MetricsDecorator",
    "localization_trace_var",
]
