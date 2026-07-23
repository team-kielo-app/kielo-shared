"""ElevenLabs TTS provider for the shared Python TTS seam."""

from __future__ import annotations

import time
from typing import Any, Optional
from urllib.parse import quote

import httpx

from kielo_shared.seam.tts.types import Error, ErrorClass, Request, Result


_DEFAULT_ENDPOINT = "https://api.elevenlabs.io/v1/text-to-speech"
_DEFAULT_MODEL = "eleven_flash_v2_5"


class ElevenLabsTTSProvider:
    """Calls ElevenLabs streaming TTS and returns buffered MP3 bytes."""

    def __init__(
        self,
        api_key: str,
        http_client: Optional[httpx.AsyncClient] = None,
        *,
        endpoint: str = _DEFAULT_ENDPOINT,
        default_model: str = _DEFAULT_MODEL,
        language_code: str = "",
    ) -> None:
        self._api_key = api_key
        self._client = http_client
        self._endpoint = endpoint.rstrip("/")
        self._default_model = default_model
        self._language_code = language_code.strip().lower()

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
        if request.speed > 0:
            payload["voice_settings"] = {
                "stability": 0.5,
                "similarity_boost": 0.75,
                "speed": max(0.7, min(float(request.speed), 1.2)),
            }
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
