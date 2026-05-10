"""Python LLM seam metrics decorator.

Mirrors `kielo_shared.seam.tts.metrics`. Emits the shared
`kielo_llm_calls_total` family — same labels as the engine-side
`kielo_shared.observability.metrics::llm_emit` family so dashboards
aggregate Python (`kielo_shared.llm` engine path) and convo
python_agent calls under one metric name.

Important: this decorator emits via the engine-side LLM family
(`kielo_llm_calls_total{provider, task, cache_policy, cached, error}`)
NOT a separate counter, so aggregate views work without label
remapping.
"""
from __future__ import annotations

import logging
import time
from typing import AsyncIterator, Callable

from kielo_shared.seam.llm.types import (
    Provider,
    Request,
    Result,
    class_of,
)


logger = logging.getLogger(__name__)


class MetricsDecorator:
    def __init__(
        self,
        inner: Provider,
        provider_tag: Callable[[Request], str] | None = None,
    ) -> None:
        self._inner = inner
        self._provider_tag = provider_tag

    @property
    def provider_id(self) -> str:
        return self._inner.provider_id

    def _provider_label(self, request: Request) -> str:
        if self._provider_tag is not None:
            return self._provider_tag(request)
        return self._inner.provider_id

    def _labels(self, request: Request) -> tuple[str, str, str, str]:
        return (
            self._provider_label(request),
            request.task or "generic",
            "none",
            "false",
        )

    async def generate(self, request: Request) -> Result:
        provider, task, cache_policy, cached = self._labels(request)
        started = time.perf_counter()
        err: BaseException | None = None
        try:
            return await self._inner.generate(request)
        except BaseException as exc:
            err = exc
            raise
        finally:
            self._emit(
                provider=provider,
                task=task,
                cache_policy=cache_policy,
                cached=cached,
                err=err,
                elapsed=time.perf_counter() - started,
            )

    async def generate_stream(self, request: Request) -> AsyncIterator[str]:
        """Wrap a streaming provider call. Forwards chunks as the
        inner yields them; emits one metric record per stream when
        iteration completes (cleanly OR via raise). Raises
        AttributeError if the inner provider doesn't implement
        `generate_stream` — no silent fallback to one-shot.
        """
        provider, task, cache_policy, cached = self._labels(request)
        if not hasattr(self._inner, "generate_stream"):
            raise AttributeError(
                "inner provider does not implement generate_stream"
            )
        inner_stream = self._inner.generate_stream(request)  # type: ignore[attr-defined]

        started = time.perf_counter()
        err: BaseException | None = None
        try:
            async for chunk in inner_stream:
                yield chunk
        except BaseException as exc:
            err = exc
            raise
        finally:
            self._emit(
                provider=provider,
                task=task,
                cache_policy=cache_policy,
                cached=cached,
                err=err,
                elapsed=time.perf_counter() - started,
            )

    @staticmethod
    def _emit(
        *,
        provider: str,
        task: str,
        cache_policy: str,
        cached: str,
        err: BaseException | None,
        elapsed: float,
    ) -> None:
        try:
            from kielo_shared.observability.metrics import (
                LLM_CALLS_TOTAL,
                LLM_LATENCY_S,
                PROMETHEUS_AVAILABLE,
            )
        except Exception:  # noqa: BLE001
            return
        if not PROMETHEUS_AVAILABLE or LLM_CALLS_TOTAL is None:
            return
        try:
            LLM_CALLS_TOTAL.labels(
                provider=provider,
                task=task,
                cache_policy=cache_policy,
                cached=cached,
                error=class_of(err) if err is not None else "",
            ).inc()
            LLM_LATENCY_S.labels(
                provider=provider, task=task, cached=cached
            ).observe(elapsed)
        except Exception as exc:  # noqa: BLE001
            logger.debug("llm metrics fanout failed: %s", exc)


def with_metrics(inner: Provider) -> MetricsDecorator:
    return MetricsDecorator(inner)
