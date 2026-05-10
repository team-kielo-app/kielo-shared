"""OpenAI chat-completions provider for the Python LLM seam.

Wraps `openai.AsyncOpenAI.chat.completions.create` for callers
that prefer chat shape over the Gemini `generate_content` shape.
Mapping:

  ``Request.system_prompt`` → role=system message
  ``Request.prompt``        → role=user message
  ``Request.response_mime_type="application/json"`` → response_format={"type":"json_object"}
  ``Request.temperature``   → passed through when non-None
  ``Request.model``         → required; no implicit default

Caller injects an `AsyncOpenAI` client (so existing connection
pool / retries stay caller-side).
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


class OpenAIChatProvider:
    """Stateless beyond the injected client. One provider per
    process is plenty — the client itself owns the connection
    pool.
    """

    def __init__(
        self,
        client: Any,
        *,
        default_model: str = "gpt-4o-mini",
    ) -> None:
        self._client = client
        self._default_model = default_model

    @property
    def provider_id(self) -> str:
        return f"openai-chat:{self._default_model}"

    def _messages(self, request: Request) -> list[dict]:
        msgs: list[dict] = []
        if request.system_prompt:
            msgs.append({"role": "system", "content": request.system_prompt})
        msgs.append({"role": "user", "content": request.prompt})
        return msgs

    def _common_kwargs(self, request: Request) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model": request.model or self._default_model,
            "messages": self._messages(request),
        }
        if request.response_mime_type == "application/json":
            kwargs["response_format"] = {"type": "json_object"}
        if request.temperature is not None:
            kwargs["temperature"] = request.temperature
        return kwargs

    async def generate(self, request: Request) -> Result:
        if not request.prompt:
            raise Error(
                ErrorClass.INVALID_REQUEST,
                RuntimeError("empty prompt"),
            )
        if self._client is None:
            raise Error(
                ErrorClass.INVALID_REQUEST,
                RuntimeError("OpenAI client not configured"),
            )

        started = time.perf_counter()
        try:
            completion = await self._client.chat.completions.create(
                **self._common_kwargs(request),
            )
        except Error:
            raise
        except Exception as exc:  # noqa: BLE001
            raise Error(_classify_openai_exception(exc), exc) from exc

        text = _extract_chat_text(completion)
        if not text:
            raise Error(
                ErrorClass.EMPTY_RESPONSE,
                RuntimeError("openai chat returned empty content"),
            )
        return Result(
            raw_text=text,
            provider=self.provider_id,
            latency_ms=int((time.perf_counter() - started) * 1000),
        )

    async def generate_stream(self, request: Request) -> AsyncIterator[str]:
        """Stream chat-completion delta tokens. Yields the
        ``choices[0].delta.content`` strings as the upstream
        produces them. Wrap in `with_metrics(...)` so the per-call
        record fires when iteration completes.
        """
        if not request.prompt:
            raise Error(
                ErrorClass.INVALID_REQUEST,
                RuntimeError("empty prompt"),
            )
        if self._client is None:
            raise Error(
                ErrorClass.INVALID_REQUEST,
                RuntimeError("OpenAI client not configured"),
            )

        try:
            stream = await self._client.chat.completions.create(
                stream=True,
                **self._common_kwargs(request),
            )
        except Error:
            raise
        except Exception as exc:  # noqa: BLE001
            raise Error(_classify_openai_exception(exc), exc) from exc

        try:
            async for chunk in stream:
                token = _extract_chat_delta_text(chunk)
                if token:
                    yield token
        except Error:
            raise
        except Exception as exc:  # noqa: BLE001
            raise Error(_classify_openai_exception(exc), exc) from exc


def _extract_chat_text(completion: Any) -> Optional[str]:
    choices = getattr(completion, "choices", None) or []
    if not choices:
        return None
    msg = getattr(choices[0], "message", None)
    if msg is None:
        return None
    return getattr(msg, "content", None)


def _extract_chat_delta_text(chunk: Any) -> Optional[str]:
    choices = getattr(chunk, "choices", None) or []
    if not choices:
        return None
    delta = getattr(choices[0], "delta", None)
    if delta is None:
        return None
    return getattr(delta, "content", None)


def _classify_openai_exception(exc: BaseException) -> ErrorClass:
    """Map OpenAI SDK exceptions to a bounded ErrorClass. Matches
    on class name + message because the SDK's exception hierarchy
    moves between versions; substring matching keeps label
    vocabulary stable.
    """
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    if "timeout" in name or "timeout" in msg:
        return ErrorClass.TIMEOUT
    if "connect" in name or "connect" in msg or "dns" in msg:
        return ErrorClass.CONNECTION
    if "rate" in name or "rate limit" in msg or "429" in msg:
        return ErrorClass.SERVER_ERROR
    if "auth" in name or "unauthorized" in msg or "401" in msg or "403" in msg:
        return ErrorClass.CLIENT_ERROR
    if "5" in msg and ("server" in msg or "internal" in msg):
        return ErrorClass.SERVER_ERROR
    return ErrorClass.PROVIDER_ERROR
