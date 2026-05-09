"""Composable LLMProvider decorators."""
from __future__ import annotations

import logging
import time
import uuid
from contextvars import ContextVar
from typing import Callable

from kielo_shared.llm.provider import LLMProvider
from kielo_shared.llm.types import LLMRequest, LLMResult


logger = logging.getLogger(__name__)


# Engine middleware sets this per-request; decorator picks it up.
llm_trace_var: ContextVar[str] = ContextVar("llm_trace_id", default="")


# ────────────────────────────── Metrics ──────────────────────────────────


MetricsEmit = Callable[[dict], None]


def _default_emit(record: dict) -> None:
    logger.info("llm_call %s", record)


class LLMMetricsDecorator:
    """One structured record per LLM call.

    Record shape:
      provider, task, prompt_version, cache_policy, cached, latency_ms,
      char_count_in, char_count_out, error.
    """

    def __init__(
        self,
        inner: LLMProvider,
        *,
        emit: MetricsEmit | None = None,
    ) -> None:
        self._inner = inner
        self._emit = emit or _default_emit

    @property
    def provider_id(self) -> str:
        return self._inner.provider_id

    async def generate(self, request: LLMRequest) -> LLMResult:
        start = time.perf_counter()
        char_in = len(request.system_prompt or "") + len(request.user_prompt or "")
        error: str | None = None
        result: LLMResult | None = None
        try:
            result = await self._inner.generate(request)
            return result
        except Exception as exc:  # noqa: BLE001
            error = type(exc).__name__
            raise
        finally:
            self._emit(
                {
                    "provider": self.provider_id,
                    "task": request.task,
                    "prompt_version": request.prompt_version,
                    "cache_policy": request.cache_policy,
                    "cached": bool(result and result.cached),
                    "latency_ms": int((time.perf_counter() - start) * 1000),
                    "char_count_in": char_in,
                    "char_count_out": len(result.text or "") if result else 0,
                    "error": error,
                }
            )


# ─────────────────────────── Correlation ─────────────────────────────────


class LLMCorrelationDecorator:
    """Stamp a correlation id onto results that don't already carry one.

    Sources, in order:
      1. Inner provider's stamped id (preserved if non-empty)
      2. `llm_trace_var` contextvar (request-scoped middleware)
      3. fresh uuid4
    """

    def __init__(self, inner: LLMProvider) -> None:
        self._inner = inner

    @property
    def provider_id(self) -> str:
        return self._inner.provider_id

    async def generate(self, request: LLMRequest) -> LLMResult:
        result = await self._inner.generate(request)
        if result.correlation_id:
            return result
        trace_id = (llm_trace_var.get() or "").strip() or uuid.uuid4().hex
        return LLMResult(
            text=result.text,
            parsed=result.parsed,
            provider=result.provider,
            cached=result.cached,
            latency_ms=result.latency_ms,
            correlation_id=trace_id,
            metadata=result.metadata,
        )


__all__ = [
    "LLMCorrelationDecorator",
    "LLMMetricsDecorator",
    "llm_trace_var",
]
