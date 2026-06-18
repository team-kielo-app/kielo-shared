"""Gemini provider via `google.genai` Python SDK.

Wraps `client.aio.models.generate_content(...)`. Caller passes
`response_mime_type` / `response_schema` / `temperature` via the
seam Request; the provider builds the SDK config object and
returns the response text. Stateless beyond the API key.
"""

from __future__ import annotations

import time
from typing import Any, AsyncIterator, Optional

from kielo_shared.seam.llm.types import (
    Error,
    ErrorClass,
    Request,
    Result,
)


_DEFAULT_MODEL = "gemini-3.1-flash-lite"


class GeminiSDKProvider:
    """Constructs a `google.genai.Client` lazily and delegates to
    its async `models.generate_content`. Caller is responsible for
    holding ONE provider per process (the genai client is heavy);
    metrics decorator passes through unchanged.
    """

    def __init__(
        self,
        api_key: str,
        *,
        client: Optional[Any] = None,
        default_model: str = _DEFAULT_MODEL,
    ) -> None:
        self._api_key = api_key
        self._client = client
        self._default_model = default_model

    @property
    def provider_id(self) -> str:
        return f"gemini-sdk:{self._default_model}"

    def _resolve_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            from google import genai  # type: ignore[import-not-found]
        except Exception as exc:
            raise Error(ErrorClass.PROVIDER_ERROR, exc) from exc
        if not self._api_key:
            raise Error(
                ErrorClass.INVALID_REQUEST,
                RuntimeError("Gemini API key not configured"),
            )
        try:
            self._client = genai.Client(api_key=self._api_key)
        except Exception as exc:
            raise Error(ErrorClass.PROVIDER_ERROR, exc) from exc
        return self._client

    def _build_config(self, request: Request) -> Any:
        try:
            from google.genai import types as _genai_types  # type: ignore[import-not-found]
        except Exception as exc:
            raise Error(ErrorClass.PROVIDER_ERROR, exc) from exc

        config_kwargs: dict[str, Any] = {}
        if request.response_mime_type:
            config_kwargs["response_mime_type"] = request.response_mime_type
        if request.response_schema is not None:
            config_kwargs["response_schema"] = request.response_schema
        if request.temperature is not None:
            config_kwargs["temperature"] = request.temperature
        if request.system_prompt:
            config_kwargs["system_instruction"] = request.system_prompt

        if not config_kwargs:
            return None
        return _genai_types.GenerateContentConfig(**config_kwargs)

    async def generate(self, request: Request) -> Result:
        if not request.prompt:
            raise Error(
                ErrorClass.INVALID_REQUEST,
                RuntimeError("empty prompt"),
            )
        client = self._resolve_client()
        config = self._build_config(request)
        model = request.model or self._default_model

        started = time.perf_counter()
        try:
            response = await client.aio.models.generate_content(
                model=model,
                contents=request.prompt,
                config=config,
            )
        except Error:
            raise
        except Exception as exc:
            raise Error(_classify_genai_exception(exc), exc) from exc

        text = getattr(response, "text", None)
        if not text:
            raise Error(
                ErrorClass.EMPTY_RESPONSE,
                RuntimeError("gemini sdk returned empty text"),
            )
        return Result(
            raw_text=str(text),
            provider=self.provider_id,
            latency_ms=int((time.perf_counter() - started) * 1000),
        )

    async def generate_stream(self, request: Request) -> AsyncIterator[str]:
        """Stream text tokens via the genai SDK's
        `generate_content_stream`. Yields raw text chunks as the
        upstream produces them. Status / transport errors raise the
        same `Error` taxonomy as one-shot `generate`.
        """
        if not request.prompt:
            raise Error(
                ErrorClass.INVALID_REQUEST,
                RuntimeError("empty prompt"),
            )
        client = self._resolve_client()
        config = self._build_config(request)
        model = request.model or self._default_model

        try:
            async_stream = await client.aio.models.generate_content_stream(
                model=model,
                contents=request.prompt,
                config=config,
            )
        except Error:
            raise
        except Exception as exc:
            raise Error(_classify_genai_exception(exc), exc) from exc

        try:
            async for chunk in async_stream:
                text = getattr(chunk, "text", None)
                if text:
                    yield str(text)
        except Error:
            raise
        except Exception as exc:
            raise Error(_classify_genai_exception(exc), exc) from exc


def _classify_genai_exception(exc: BaseException) -> ErrorClass:
    """Map a `google.genai`-raised exception to a bounded
    ErrorClass. The SDK doesn't expose a stable type hierarchy; we
    match on the exception class name so dependency churn doesn't
    break label vocabulary."""
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    if "timeout" in name or "timeout" in msg or "deadline" in msg:
        return ErrorClass.TIMEOUT
    if "connection" in name or "connection" in msg or "resolve" in msg:
        return ErrorClass.CONNECTION
    if "permission" in msg or "unauthorized" in msg or "401" in msg or "403" in msg:
        return ErrorClass.CLIENT_ERROR
    if "5" in msg and ("server" in msg or "internal" in msg):
        return ErrorClass.SERVER_ERROR
    return ErrorClass.PROVIDER_ERROR
