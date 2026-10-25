"""kielo_shared.seam.tts — Python-side TTS seam.

Mirror of `kielo-shared/seam/tts` (Go). Same scope discipline:
providers turn (text, voice, speed) into audio bytes. Caching,
circuit breakers, voice normalization stay in the caller. The seam
is the choke point for outbound TTS HTTP traffic, NOT a kitchen sink.

Vertical slice today:
  * OpenAITTSProvider — POST to api.openai.com/v1/audio/speech.
  * ElevenLabsTTSProvider — POST to ElevenLabs streaming TTS.
  * GeminiTTSProvider — Gemini generate_content audio, language pinned
    via speech_config.language_code (see gemini_provider / languages).
  * MetricsDecorator   — emits `kielo_tts_calls_total` mirroring the
    Go-side family registered in
    `kielo-shared/observe/metrics/tts.go` so cross-process dashboards
    aggregate Go (kielo-convo) + Python (engine) calls.

Caller shape (mirrors the LLM seam pattern):

    from kielo_shared.seam.tts import (
        OpenAITTSProvider, Request, with_metrics,
    )

    provider = with_metrics(OpenAITTSProvider(api_key, http_client))
    result = await provider.synthesize(Request(
        text="...", voice_id="alloy", task="klearn_tts_baseword",
    ))
"""

from __future__ import annotations

from kielo_shared.seam.tts.elevenlabs_provider import ElevenLabsTTSProvider
from kielo_shared.seam.tts.gemini_provider import (
    GeminiSpeechClient,
    GeminiTTSProvider,
    GenAISpeechClient,
)
from kielo_shared.seam.tts.languages import LANGUAGE_CODES, language_tag
from kielo_shared.seam.tts.metrics import MetricsDecorator, with_metrics
from kielo_shared.seam.tts.openai_provider import OpenAITTSProvider
from kielo_shared.seam.tts.types import (
    Error,
    ErrorClass,
    Provider,
    Request,
    Result,
    StreamingProvider,
    class_of,
)

__all__ = [
    "LANGUAGE_CODES",
    "ElevenLabsTTSProvider",
    "Error",
    "ErrorClass",
    "GeminiSpeechClient",
    "GeminiTTSProvider",
    "GenAISpeechClient",
    "MetricsDecorator",
    "OpenAITTSProvider",
    "Provider",
    "Request",
    "Result",
    "StreamingProvider",
    "class_of",
    "language_tag",
    "with_metrics",
]
