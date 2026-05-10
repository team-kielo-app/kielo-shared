"""OpenAI TTS provider — mirrors `kielo-shared/seam/tts/openai.go`.

Uses httpx.AsyncClient for outbound calls. Caller injects the
client (timeout / proxy / transport policy stay caller-side).
"""
from __future__ import annotations

import time
from typing import Any, AsyncIterator, Optional

import httpx

from kielo_shared.seam.tts.types import (
    Error,
    ErrorClass,
    Request,
    Result,
)


_DEFAULT_ENDPOINT = "https://api.openai.com/v1/audio/speech"
_DEFAULT_MODEL = "tts-1"


class OpenAITTSProvider:
    """Calls OpenAI /v1/audio/speech and returns raw audio bytes.

    Stateless beyond the injected ``http_client`` + API key. Caller
    owns retry / circuit-breaker policy.
    """

    def __init__(
        self,
        api_key: str,
        http_client: Optional[httpx.AsyncClient] = None,
        *,
        endpoint: str = _DEFAULT_ENDPOINT,
        default_model: str = _DEFAULT_MODEL,
    ) -> None:
        self._api_key = api_key
        self._client = http_client
        self._owns_client = http_client is None
        self._endpoint = endpoint
        self._default_model = default_model

    def provider_id(self, request: Request) -> str:
        """Round-tripped onto Result.provider so metrics split by
        model version. Format: ``openai-tts:<model>``."""
        model = request.model or self._default_model
        return f"openai-tts:{model}"

    def _validate_request(self, request: Request) -> None:
        if not self._api_key:
            raise Error(ErrorClass.CLIENT_ERROR, RuntimeError("OpenAI API key not configured"))
        if not request.text:
            raise Error(ErrorClass.CLIENT_ERROR, RuntimeError("empty text"))

    def _build_payload(self, request: Request) -> dict[str, Any]:
        model = request.model or self._default_model
        payload: dict[str, Any] = {
            "model": model,
            "voice": request.voice_id,
            "input": request.text,
            "response_format": "mp3",
        }
        if request.speed > 0:
            payload["speed"] = request.speed
        if request.instructions and model == "gpt-4o-mini-tts":
            payload["instructions"] = request.instructions
        return payload

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    async def synthesize(self, request: Request) -> Result:
        self._validate_request(request)
        payload = self._build_payload(request)

        client = self._client
        owns = client is None
        if client is None:
            client = httpx.AsyncClient(timeout=30.0)

        started = time.perf_counter()
        try:
            try:
                response = await client.post(self._endpoint, json=payload, headers=self._headers())
            except httpx.TimeoutException as exc:
                raise Error(ErrorClass.TIMEOUT, exc) from exc
            except httpx.RequestError as exc:
                raise Error(ErrorClass.CONNECTION, exc) from exc

            if response.status_code != 200:
                cls = (
                    ErrorClass.SERVER_ERROR if response.status_code >= 500 else ErrorClass.CLIENT_ERROR
                )
                raise Error(
                    cls,
                    RuntimeError(
                        f"openai tts status={response.status_code} body={response.text}"
                    ),
                )

            audio = response.content
            if not audio:
                raise Error(ErrorClass.EMPTY_RESPONSE, RuntimeError("openai tts empty body"))

            return Result(
                audio=audio,
                provider=self.provider_id(request),
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
        finally:
            if owns:
                await client.aclose()

    async def synthesize_stream(self, request: Request) -> AsyncIterator[bytes]:
        """Stream audio bytes as the upstream produces them.

        Caller iterates the returned async generator; the seam's
        ``MetricsDecorator`` wraps the iteration to emit metrics
        when the stream completes (or raises). Status and transport
        errors raise the same ``Error`` class as ``synthesize``.

        Caller MUST own the http client; we do NOT auto-spawn one
        for streams because closing the client mid-iteration would
        truncate the body. If the caller passes an
        ``http_client=None`` provider, ``RuntimeError`` is raised
        eagerly.
        """
        self._validate_request(request)
        if self._client is None:
            raise Error(
                ErrorClass.CLIENT_ERROR,
                RuntimeError("synthesize_stream requires a caller-owned http_client"),
            )
        payload = self._build_payload(request)

        try:
            stream_ctx = self._client.stream(
                "POST", self._endpoint, json=payload, headers=self._headers()
            )
        except httpx.TimeoutException as exc:
            raise Error(ErrorClass.TIMEOUT, exc) from exc
        except httpx.RequestError as exc:
            raise Error(ErrorClass.CONNECTION, exc) from exc

        async with stream_ctx as response:
            if response.status_code != 200:
                error_body = await response.aread()
                cls = (
                    ErrorClass.SERVER_ERROR if response.status_code >= 500 else ErrorClass.CLIENT_ERROR
                )
                raise Error(
                    cls,
                    RuntimeError(
                        f"openai tts status={response.status_code} body={error_body.decode(errors='replace')}"
                    ),
                )

            try:
                async for chunk in response.aiter_bytes():
                    if chunk:
                        yield chunk
            except httpx.TimeoutException as exc:
                raise Error(ErrorClass.TIMEOUT, exc) from exc
            except httpx.RequestError as exc:
                raise Error(ErrorClass.CONNECTION, exc) from exc
