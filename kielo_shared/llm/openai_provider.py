"""OpenAI-backed LLM provider — Phase D.

Two execution lanes, picked from `LLMRequest.response_schema`:
  * No schema → text generation. Caller injects a function matching
    engine `llm_service.generate_text(system, user, variables) -> str|None`.
  * Schema present → JSON output. Caller injects a function matching
    engine `llm_service.generate_json_output(system, user, schema_model,
    variables) -> BaseModel|None`.

The provider stays SDK-free; engine wires both lanes from its existing
`llm_service` instance at construction time.
"""
from __future__ import annotations

import logging
import time
from typing import Awaitable, Callable

from kielo_shared.llm.types import LLMRequest, LLMResult


logger = logging.getLogger(__name__)


# Function signatures matching engine `LLMService`. Stays loose typed so
# tests can plug stubs without importing engine internals.
OpenAITextGenerator = Callable[
    [str, str, dict | None],
    Awaitable[str | None],
]

OpenAIJsonGenerator = Callable[
    [str, str, type, dict | None],
    Awaitable["object | None"],
]


class OpenAILLMProvider:
    """Bridges `kielo_shared.llm` to engine `llm_service`.

    Both generators are required: text path for prompts without a schema,
    json path for schemaful prompts. If the JSON path isn't wired, schemaful
    requests fall back to the text generator and the caller gets unparsed
    text in `result.text` (with `result.parsed=None`).
    """

    def __init__(
        self,
        text_generator: OpenAITextGenerator,
        *,
        json_generator: OpenAIJsonGenerator | None = None,
        provider_id: str = "openai:gpt-4o-mini@phase-d",
    ) -> None:
        self._text = text_generator
        self._json = json_generator
        self._provider_id = provider_id

    @property
    def provider_id(self) -> str:
        return self._provider_id

    async def generate(self, request: LLMRequest) -> LLMResult:
        started = time.perf_counter()

        if request.response_schema is not None and self._json is not None:
            text, parsed = await self._call_json(request)
        else:
            text, parsed = await self._call_text(request)

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return LLMResult(
            text=text,
            parsed=parsed,
            provider=self._provider_id,
            cached=False,
            latency_ms=elapsed_ms,
            correlation_id="",
            metadata={
                "task": request.task,
                "prompt_version": request.prompt_version,
            },
        )

    # ──────────────────────────── lanes ──────────────────────────────────

    async def _call_text(
        self, request: LLMRequest
    ) -> tuple[str, object | None]:
        raw = await self._text(
            request.system_prompt,
            request.user_prompt,
            dict(request.variables or {}),
        )
        return (raw or ""), None

    async def _call_json(
        self, request: LLMRequest
    ) -> tuple[str, object | None]:
        # Schema is a Pydantic class today; pass through verbatim. The engine
        # `generate_json_output` returns either a Pydantic instance OR a
        # dict (LangChain's JsonOutputParser produces dicts) — handle both.
        schema_class = _resolve_schema_class(request.response_schema)
        if schema_class is None or self._json is None:
            return await self._call_text(request)
        parsed = await self._json(
            request.system_prompt,
            request.user_prompt,
            schema_class,
            dict(request.variables or {}),
        )
        if parsed is None:
            return "", None
        # Build a JSON-shaped `text` representation so:
        #   * Cache writes don't skip on empty text.
        #   * Callers that want raw text get a usable string.
        # Pydantic v2 path:
        dump = getattr(parsed, "model_dump_json", None)
        if callable(dump):
            try:
                return dump(), parsed
            except Exception:  # noqa: BLE001
                pass
        # Plain dict / list (LangChain JsonOutputParser path):
        if isinstance(parsed, (dict, list)):
            try:
                import json as _json
                return _json.dumps(parsed, ensure_ascii=False, default=str), parsed
            except Exception:  # noqa: BLE001
                return "", parsed
        return "", parsed


def _resolve_schema_class(schema: object | None) -> type | None:
    """Translate the request's `response_schema` field to a Pydantic class.

    Phase D accepts either:
      * A Pydantic `BaseModel` subclass directly (preferred for engine
        callers that already have one).
      * A dict carrying a `__pydantic__` key with the class — escape hatch
        for callers that build the request from JSON.
    """
    if schema is None:
        return None
    if isinstance(schema, type):
        return schema
    if isinstance(schema, dict):
        candidate = schema.get("__pydantic__")
        if isinstance(candidate, type):
            return candidate
    return None


__all__ = ["OpenAIJsonGenerator", "OpenAILLMProvider", "OpenAITextGenerator"]
