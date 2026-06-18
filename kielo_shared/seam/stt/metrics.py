"""STT seam metrics decorator.

Emits `kielo_stt_calls_total{provider,task,language,error}` per
factory call. Records keyterm count via
`kielo_stt_keyterms_count{provider,task,language}` Histogram so
keyterm-prompting effectiveness can be tracked WITHOUT exposing
keyterm values as labels (cardinality control).
"""

from __future__ import annotations

import logging
from typing import Any

from kielo_shared.seam.stt.types import (
    RealtimeSTTProvider,
    RealtimeSTTRequest,
    class_of,
)


logger = logging.getLogger(__name__)


class MetricsDecorator:
    """Wraps a `RealtimeSTTProvider`. ``create_realtime_stt`` records
    one counter increment per call; the inner provider's STT object
    is returned unchanged.
    """

    def __init__(self, inner: RealtimeSTTProvider) -> None:
        self._inner = inner

    @property
    def provider_id(self) -> str:
        return self._inner.provider_id

    def create_realtime_stt(self, request: RealtimeSTTRequest) -> Any:
        provider = self._inner.provider_id
        task = request.task or "generic"
        language = request.language or "unknown"
        err: BaseException | None = None
        try:
            stt = self._inner.create_realtime_stt(request)
        except BaseException as exc:
            err = exc
            raise
        finally:
            self._emit(
                provider=provider,
                task=task,
                language=language,
                err=err,
                keyterm_count=len(request.keyterms),
            )
        return stt

    @staticmethod
    def _emit(
        *,
        provider: str,
        task: str,
        language: str,
        err: BaseException | None,
        keyterm_count: int,
    ) -> None:
        try:
            from kielo_shared.observability.metrics import (
                PROMETHEUS_AVAILABLE,
                STT_CALLS_TOTAL,
                STT_KEYTERMS_COUNT,
            )
        except Exception:
            return
        if not PROMETHEUS_AVAILABLE or STT_CALLS_TOTAL is None:
            return
        try:
            STT_CALLS_TOTAL.labels(
                provider=provider,
                task=task,
                language=language,
                error=class_of(err) if err is not None else "",
            ).inc()
            STT_KEYTERMS_COUNT.labels(
                provider=provider, task=task, language=language
            ).observe(float(keyterm_count))
        except Exception as exc:
            logger.debug("stt metrics fanout failed: %s", exc)


def with_metrics(inner: RealtimeSTTProvider) -> MetricsDecorator:
    return MetricsDecorator(inner)
