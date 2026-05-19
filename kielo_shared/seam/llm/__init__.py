"""kielo_shared.seam.llm — Python LLM seam.

Mirror of `kielo-shared/seam/llm/` (Go). Phase D+3 vertical slice
covers Gemini via the `google.genai` SDK. Same scope discipline as
the TTS/STT seams — providers do ONE thing: turn a prompt into raw
text. Caching, retry, validation stay in the caller.

Distinct from `kielo_shared.llm` (the older registry-based engine
seam). The `kielo_shared.llm` package owns OpenAI + complex
decorator stack; this `kielo_shared.seam.llm` package owns Go-style
narrow factory providers.

Caller shape::

    from kielo_shared.seam.llm import (
        GeminiSDKProvider, Request, with_metrics,
    )

    provider = with_metrics(GeminiSDKProvider(api_key=k))
    result = await provider.generate(Request(
        prompt="...",
        model="gemini-3.1-flash-lite",
        response_mime_type="application/json",
        task="convo_hint_engine",
    ))
"""
from __future__ import annotations

from kielo_shared.seam.llm.types import (
    Error,
    ErrorClass,
    Provider,
    Request,
    Result,
    StreamingProvider,
    class_of,
)
from kielo_shared.seam.llm.gemini_provider import GeminiSDKProvider
from kielo_shared.seam.llm.openai_provider import OpenAIChatProvider
from kielo_shared.seam.llm.metrics import MetricsDecorator, with_metrics


__all__ = [
    "Error",
    "ErrorClass",
    "GeminiSDKProvider",
    "MetricsDecorator",
    "OpenAIChatProvider",
    "Provider",
    "Request",
    "Result",
    "StreamingProvider",
    "class_of",
    "with_metrics",
]
