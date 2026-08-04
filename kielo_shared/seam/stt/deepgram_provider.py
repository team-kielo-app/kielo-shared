"""Deepgram LiveKit STT provider — Phase STT-1.

Wraps `livekit.plugins.deepgram.STT(...)` construction so callers
don't import the Deepgram plugin directly. Behavior-preserving:
the seam mirrors the pre-D+3 voice_pipeline call exactly (same
field set, same defaults), with two additions:
  * Bounded language validation (fi / sv) raised as a seam Error
    instead of a free-form ValueError, so the metrics decorator
    can attach `error="invalid_language"`.
  * Optional API-key env propagation (preserves the existing
    voice_pipeline side-effect of setting DEEPGRAM_API_KEY before
    construction; some plugin code paths read it from env rather
    than from the constructor).
"""

from __future__ import annotations

import os
from typing import Any

from kielo_shared.seam.stt.types import (
    Error,
    ErrorClass,
    RealtimeSTTRequest,
)


_SUPPORTED_LANGUAGES = frozenset({"fi", "sv"})


class DeepgramLiveKitSTTProvider:
    """Factory provider that returns a `livekit.plugins.deepgram.STT`.

    Stateless beyond the API key. Caller must hold the returned
    object for the lifetime of its `AgentSession`.
    """

    def __init__(
        self,
        api_key: str = "",
        *,
        propagate_api_key_to_env: bool = True,
    ) -> None:
        self._api_key = api_key
        self._propagate_api_key_to_env = propagate_api_key_to_env

    @property
    def provider_id(self) -> str:
        # Static suffix today; bump to "@stt-v2" when the provider
        # field set changes meaningfully.
        return "deepgram:livekit@stt-v1"

    def create_realtime_stt(self, request: RealtimeSTTRequest) -> Any:
        if request.language not in _SUPPORTED_LANGUAGES:
            raise Error(
                ErrorClass.INVALID_LANGUAGE,
                ValueError(
                    f"voice agent requires fi or sv learning_language_code, got "
                    f"{request.language!r}"
                ),
            )
        if not request.model:
            raise Error(
                ErrorClass.INVALID_REQUEST,
                ValueError("STT model is required"),
            )

        # Lazy import — avoids pulling livekit.plugins into kielo-shared
        # consumers that don't actually need it (engine, ingest).
        try:
            from livekit.plugins import deepgram  # type: ignore[import-not-found]
        except Exception as exc:
            raise Error(ErrorClass.PROVIDER_ERROR, exc) from exc

        if self._api_key and self._propagate_api_key_to_env:
            os.environ["DEEPGRAM_API_KEY"] = self._api_key

        try:
            return deepgram.STT(
                model=request.model,
                language=request.language or None,
                # The livekit deepgram plugin does `list(keyterm)` unguarded, so
                # None crashes it — pass [] (no biasing) when we have no keyterms.
                keyterm=list(request.keyterms) if request.keyterms else [],
                smart_format=request.smart_format,
                punctuate=request.punctuate,
                filler_words=request.filler_words,
            )
        except Error:
            raise
        except Exception as exc:
            raise Error(ErrorClass.PROVIDER_ERROR, exc) from exc
