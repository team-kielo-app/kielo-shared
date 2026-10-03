"""Gemini provider via `google.genai` Python SDK.

Wraps `client.aio.models.generate_content(...)`. Caller passes
`response_mime_type` / `response_schema` / `temperature` via the
seam Request; the provider builds the SDK config object and
returns the response text. Stateless beyond the API key.
"""

from __future__ import annotations

import time
from typing import Any, AsyncIterator, Optional

from kielo_shared import llmroute
from kielo_shared.llm.pricing import estimate_usd
from kielo_shared.llm.spend_guard import admit_paid_call, record_actual_usd
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
        family: str = "",
    ) -> None:
        """``family`` (kielo_shared.llmroute) puts the provider under the AI-models
        control plane: the model and thinking budget resolve through llmroute
        (the request's model / default_model is the fail-open default), calls are
        admitted under the family's budget and each one is rolled up as usage.
        """
        self._api_key = api_key
        self._client = client
        self._default_model = default_model
        self._family = family

    def _route(self, request: Request) -> "llmroute.Route":
        default = request.model or self._default_model
        if not self._family:
            return llmroute.Route(default)
        return llmroute.resolve(self._family, default)

    def _config(self, request: Request, thinking_budget: int) -> Any:
        config = self._build_config(request)
        if thinking_budget < 0:
            return config
        try:
            from google.genai import types as _genai_types  # type: ignore[import-not-found]
        except Exception as exc:
            raise Error(ErrorClass.PROVIDER_ERROR, exc) from exc
        if config is None:
            config = _genai_types.GenerateContentConfig()
        config.thinking_config = _genai_types.ThinkingConfig(
            thinking_budget=thinking_budget
        )
        return config

    def _record(self, model: str, usage: Any, started: float, failed: bool) -> None:
        if not self._family:
            return
        try:
            tin = int(getattr(usage, "prompt_token_count", 0) or 0)
            tout = int(getattr(usage, "candidates_token_count", 0) or 0)
            think = int(getattr(usage, "thoughts_token_count", 0) or 0)
            usd = estimate_usd(model, tin, tout, think)
            if not failed:
                record_actual_usd(usd, family=self._family)
            llmroute.record_call(
                self._family,
                model,
                input_tokens=tin,
                output_tokens=tout,
                thinking_tokens=think,
                usd=usd,
                latency_ms=(time.perf_counter() - started) * 1000,
                error=failed,
            )
        except Exception:
            pass

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
        route = self._route(request)
        config = self._config(request, route.thinking_budget)
        model = route.model

        admit_paid_call(
            getattr(request, "task", ""),
            provider=self.provider_id,
            family=self._family,
        )
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
            self._record(model, None, started, True)
            raise Error(_classify_genai_exception(exc), exc) from exc

        self._record(model, getattr(response, "usage_metadata", None), started, False)
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
        route = self._route(request)
        config = self._config(request, route.thinking_budget)
        model = route.model

        admit_paid_call(
            getattr(request, "task", ""),
            provider=self.provider_id,
            family=self._family,
        )
        started = time.perf_counter()
        usage: Any = None
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
                usage = getattr(chunk, "usage_metadata", None) or usage
                text = getattr(chunk, "text", None)
                if text:
                    yield str(text)
        except Error:
            raise
        except Exception as exc:
            self._record(model, usage, started, True)
            raise Error(_classify_genai_exception(exc), exc) from exc
        self._record(model, usage, started, False)


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
