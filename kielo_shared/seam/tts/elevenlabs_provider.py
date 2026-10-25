"""ElevenLabs TTS provider for the shared Python TTS seam."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

import httpx

from kielo_shared.seam.tts.types import Error, ErrorClass, Request, Result

_DEFAULT_ENDPOINT = "https://api.elevenlabs.io/v1/text-to-speech"
_DEFAULT_MODEL = "eleven_flash_v2_5"
DEFAULT_STABILITY = 0.5
DEFAULT_SIMILARITY_BOOST = 0.75


def _first_set(*values: float | None) -> float | None:
    for value in values:
        if value is not None:
            return float(value)
    return None


class ElevenLabsTTSProvider:
    """Calls ElevenLabs streaming TTS and returns buffered MP3 bytes.

    ``stability`` / ``similarity_boost`` default to 0.5 / 0.75 when voice_settings
    is sent; a provider-level value or a per-request one (``Request.stability``,
    ``Request.similarity_boost``, which wins) overrides them. Setting either one
    sends voice_settings even without a speed.
    """

    def __init__(
        self,
        api_key: str,
        http_client: httpx.AsyncClient | None = None,
        *,
        endpoint: str = _DEFAULT_ENDPOINT,
        default_model: str = _DEFAULT_MODEL,
        language_code: str = "",
        stability: float | None = None,
        similarity_boost: float | None = None,
    ) -> None:
        self._api_key = api_key
        self._client = http_client
        self._endpoint = endpoint.rstrip("/")
        self._default_model = default_model
        self._language_code = language_code.strip().lower()
        self._stability = stability
        self._similarity_boost = similarity_boost

    def provider_id(self, request: Request) -> str:
        model = request.model or self._default_model
        return f"elevenlabs-tts:{model}"

    def _validate_request(self, request: Request) -> None:
        if not self._api_key:
            raise Error(
                ErrorClass.CLIENT_ERROR,
                RuntimeError("ElevenLabs API key not configured"),
            )
        if not request.text:
            raise Error(ErrorClass.CLIENT_ERROR, RuntimeError("empty text"))
        if not request.voice_id:
            raise Error(
                ErrorClass.CLIENT_ERROR,
                RuntimeError("ElevenLabs voice ID not configured"),
            )

    def _build_payload(self, request: Request) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "text": request.text,
            "model_id": request.model or self._default_model,
        }
        model = request.model or self._default_model
        language_code = (request.language_code or self._language_code).strip().lower()
        if language_code and model != "eleven_multilingual_v2":
            payload["language_code"] = language_code
        stability = _first_set(request.stability, self._stability)
        similarity_boost = _first_set(request.similarity_boost, self._similarity_boost)
        if request.speed > 0 or stability is not None or similarity_boost is not None:
            voice_settings: dict[str, Any] = {
                "stability": DEFAULT_STABILITY if stability is None else stability,
                "similarity_boost": (
                    DEFAULT_SIMILARITY_BOOST
                    if similarity_boost is None
                    else similarity_boost
                ),
            }
            if request.speed > 0:
                voice_settings["speed"] = max(0.7, min(float(request.speed), 1.2))
            payload["voice_settings"] = voice_settings
        return payload

    def _headers(self) -> dict[str, str]:
        return {
            "xi-api-key": self._api_key,
            "Content-Type": "application/json",
        }

    async def synthesize(self, request: Request) -> Result:
        self._validate_request(request)
        client = self._client
        owns = client is None
        if client is None:
            from kielo_shared.http import internal_client_async

            client = internal_client_async(api_key=None, timeout=30.0)

        url = (
            f"{self._endpoint}/{quote(request.voice_id, safe='')}/stream"
            "?output_format=mp3_44100_128"
        )
        started = time.perf_counter()
        try:
            try:
                response = await client.post(
                    url,
                    json=self._build_payload(request),
                    headers=self._headers(),
                )
            except httpx.TimeoutException as exc:
                raise Error(ErrorClass.TIMEOUT, exc) from exc
            except httpx.RequestError as exc:
                raise Error(ErrorClass.CONNECTION, exc) from exc

            if response.status_code != 200:
                error_class = (
                    ErrorClass.SERVER_ERROR
                    if response.status_code >= 500
                    else ErrorClass.CLIENT_ERROR
                )
                raise Error(
                    error_class,
                    RuntimeError(
                        "elevenlabs tts status="
                        f"{response.status_code} body={response.text}"
                    ),
                )

            audio = response.content
            if not audio:
                raise Error(
                    ErrorClass.EMPTY_RESPONSE,
                    RuntimeError("elevenlabs tts empty body"),
                )
            return Result(
                audio=audio,
                provider=self.provider_id(request),
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        finally:
            if owns:
                await client.aclose()
