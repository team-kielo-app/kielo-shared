"""kielo_shared.seam.stt — Python real-time STT seam.

Phase STT-1: factory seam for `livekit.plugins.deepgram.STT(...)`
construction. Owns provider selection, language validation, and
construction-time metrics. Returns the LiveKit STT object unchanged
so the caller's `AgentSession(stt=...)` integration is preserved.

Out of scope today (deferred to later STT slices):
  * Generic audio-file transcription seam.
  * kielo-models Whisper provider.
  * Per-transcript runtime metrics (live latency / WER).
  * Provider fallback / runtime swap.

Caller shape:

    from kielo_shared.seam.stt import (
        DeepgramLiveKitSTTProvider, RealtimeSTTRequest, with_metrics,
    )

    stt = with_metrics(
        DeepgramLiveKitSTTProvider(api_key=cfg.deepgram_api_key)
    ).create_realtime_stt(
        RealtimeSTTRequest(
            task="convo_realtime_stt",
            model=cfg.stt_model,
            language="fi",
            keyterms=("hund", "katt"),
        )
    )
"""
from __future__ import annotations

from kielo_shared.seam.stt.types import (
    Error,
    ErrorClass,
    RealtimeSTTProvider,
    RealtimeSTTRequest,
    RealtimeSTTResult,
    class_of,
)
from kielo_shared.seam.stt.deepgram_provider import DeepgramLiveKitSTTProvider
from kielo_shared.seam.stt.metrics import MetricsDecorator, with_metrics


__all__ = [
    "DeepgramLiveKitSTTProvider",
    "Error",
    "ErrorClass",
    "MetricsDecorator",
    "RealtimeSTTProvider",
    "RealtimeSTTRequest",
    "RealtimeSTTResult",
    "class_of",
    "with_metrics",
]
