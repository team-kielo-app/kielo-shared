"""TTS seam metrics decorator.

Mirrors `kielo-shared/seam/tts/metrics.go` — emits the same metric
family (``kielo_tts_calls_total``) so cross-process dashboards
aggregate Go and Python TTS callers under one label vocabulary.
"""

from __future__ import annotations

import logging
import time
from typing import AsyncIterator, Callable

from kielo_shared.seam.tts.types import (
    Provider,
    Request,
    Result,
    class_of,
)


logger = logging.getLogger(__name__)


class MetricsDecorator:
    """Wraps a Provider and emits one ``kielo_tts_calls_total``
    increment + one ``kielo_tts_latency_seconds`` observation per
    call. Label set matches the Go-side family:
      provider / task / voice / error.
    """

    def __init__(
        self, inner: Provider, provider_tag: Callable[[Request], str] | None = None
    ):
        self._inner = inner
        if provider_tag is not None:
            self._provider_tag = provider_tag
        elif hasattr(inner, "provider_id"):
            self._provider_tag = inner.provider_id  # type: ignore[assignment]
        else:
            self._provider_tag = lambda _r: "tts:unknown"

    def _labels(self, request: Request) -> tuple[str, str, str]:
        provider = self._provider_tag(request)
        task = request.task or "generic"
        voice = request.voice_id or "default"
        return provider, task, voice

    def _emit(
        self,
        *,
        provider: str,
        task: str,
        voice: str,
        elapsed: float,
        err: BaseException | None,
    ) -> None:
        try:
            from kielo_shared.observability.metrics import (
                PROMETHEUS_AVAILABLE,
                TTS_CALLS_TOTAL,
                TTS_LATENCY_SECONDS,
            )
        except Exception:
            return
        if not PROMETHEUS_AVAILABLE or TTS_CALLS_TOTAL is None:
            return
        try:
            TTS_CALLS_TOTAL.labels(
                provider=provider,
                task=task,
                voice=voice,
                error=class_of(err) if err is not None else "",
            ).inc()
            TTS_LATENCY_SECONDS.labels(
                provider=provider, task=task, voice=voice
            ).observe(elapsed)
        except Exception as exc:
            logger.debug("tts metrics fanout failed: %s", exc)

    async def synthesize(self, request: Request) -> Result:
        provider, task, voice = self._labels(request)
        started = time.perf_counter()
        err: BaseException | None = None
        try:
            return await self._inner.synthesize(request)
        except BaseException as exc:
            err = exc
            raise
        finally:
            self._emit(
                provider=provider,
                task=task,
                voice=voice,
                elapsed=time.perf_counter() - started,
                err=err,
            )

    async def synthesize_stream(self, request: Request) -> AsyncIterator[bytes]:
        """Wrap a streaming provider call with metric emission.

        Forwards chunks as the inner provider yields them; emits one
        metric record per stream when iteration completes (cleanly
        OR via raise). Calls the inner's ``synthesize_stream``;
        raises ``AttributeError`` if the inner doesn't support
        streaming.
        """
        provider, task, voice = self._labels(request)
        if not hasattr(self._inner, "synthesize_stream"):
            raise AttributeError("inner provider does not implement synthesize_stream")
        inner_stream = self._inner.synthesize_stream(request)  # type: ignore[attr-defined]

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
                voice=voice,
                elapsed=time.perf_counter() - started,
                err=err,
            )


def with_metrics(inner: Provider) -> MetricsDecorator:
    """Recommended constructor — derives the ``provider`` label from
    the inner's ``provider_id(request)`` when available."""
    return MetricsDecorator(inner)
